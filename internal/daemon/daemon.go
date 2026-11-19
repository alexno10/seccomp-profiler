package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/baseline"
	"github.com/alexno10/seccomp-profiler/internal/diff"
	"github.com/alexno10/seccomp-profiler/internal/docker"
	"github.com/alexno10/seccomp-profiler/internal/ebpf"
	"github.com/alexno10/seccomp-profiler/internal/profile"
	"github.com/alexno10/seccomp-profiler/internal/report"
	"github.com/alexno10/seccomp-profiler/internal/selector"
	"github.com/alexno10/seccomp-profiler/internal/syscalls"
)

type Config struct {
	ControlAddr       string
	StoppedMarkerPath string
	OutputDir         string
	RawDir            string
	LockFile          string
	CommittedProfile  string
	WorkingCommitted  string
	WorkingAllowFile  string
	AllowFile         string
	Targets           string
	GroupBy           string
	ExcludeImages     []string
	ComposeProject    string
	IncludePreexist   bool
	Prune             bool
	BaselineMode      baseline.Mode
	RuntimeMode       string
	ExtraAllow        []string
	OnChange          string
	FailOn            string
	Arch              syscalls.Arch
	Kernel            string
	GeneratorVersion  string
}

type StopResponse struct {
	OK               bool   `json:"ok"`
	Error            string `json:"error,omitempty"`
	ProfilesDir      string `json:"profilesDir"`
	RawDir           string `json:"rawDir"`
	NewSyscallsCount int    `json:"newSyscallsCount"`
	HighRiskCount    int    `json:"highRiskCount"`
	GatePassed       bool   `json:"gatePassed"`
	GateReason       string `json:"gateReason"`
	MarkdownSummary  string `json:"markdownSummary"`
}

// ValidateConfig fails fast on invalid inputs instead of misbehaving after
// the whole test suite has run (e.g. a "standrad" baseline typo silently
// behaves like "none" and produces an over-strict profile).
func ValidateConfig(cfg Config) error {
	switch strings.ToLower(strings.TrimSpace(string(cfg.BaselineMode))) {
	case "", "none", "minimal", "standard":
	default:
		return fmt.Errorf("invalid baseline mode %q: must be none, minimal, or standard", cfg.BaselineMode)
	}
	switch strings.ToLower(strings.TrimSpace(cfg.RuntimeMode)) {
	case "", "auto", "none", "go", "node", "python", "java":
	default:
		return fmt.Errorf("invalid runtime mode %q: must be auto, none, go, node, python, or java", cfg.RuntimeMode)
	}
	oc := strings.ToLower(strings.TrimSpace(cfg.OnChange))
	if oc != "" && oc != "report" && oc != "fail" && oc != "update-pr" {
		return fmt.Errorf("invalid on-change %q: must be report, fail, or update-pr", cfg.OnChange)
	}
	fo := strings.ToLower(strings.TrimSpace(cfg.FailOn))
	if fo != "" && fo != "none" && fo != "high-risk" && fo != "any-new" {
		return fmt.Errorf("invalid fail-on %q: must be none, high-risk, or any-new", cfg.FailOn)
	}
	gb := strings.TrimSpace(cfg.GroupBy)
	gbLower := strings.ToLower(gb)
	switch {
	case gb == "", gbLower == "auto", gbLower == "compose-service", gbLower == "image":
	case strings.HasPrefix(gbLower, "label:"):
		if strings.TrimSpace(gb[len("label:"):]) == "" {
			return fmt.Errorf("invalid group-by %q: label key must not be empty", cfg.GroupBy)
		}
	default:
		return fmt.Errorf("invalid group-by %q: must be auto, compose-service, image, or label:<key>", cfg.GroupBy)
	}
	if strings.HasPrefix(cfg.ControlAddr, "tcp://") {
		if err := validateLoopbackTCPAddr(strings.TrimPrefix(cfg.ControlAddr, "tcp://")); err != nil {
			return err
		}
	}
	if _, err := selector.ParseTargetsInputWithErr(cfg.Targets); err != nil {
		return fmt.Errorf("invalid targets: %w", err)
	}
	for _, extra := range cfg.ExtraAllow {
		for _, tok := range strings.FieldsFunc(extra, func(r rune) bool {
			return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
		}) {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if _, ok := syscalls.NumberByName(cfg.arch(), tok); !ok {
				if _, ok := syscalls.NumberByName(syscalls.ArchAMD64, tok); !ok {
					if _, ok := syscalls.NumberByName(syscalls.ArchARM64, tok); !ok {
						return fmt.Errorf("unknown syscall %q in extra-allow (not present in the amd64 or arm64 table)", tok)
					}
				}
			}
		}
	}
	return nil
}

func validateLoopbackTCPAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid tcp control address %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("non-loopback tcp control address %q is not allowed (must bind to loopback)", addr)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("non-loopback tcp control address %q is not allowed (must bind to 127.0.0.1, ::1, or localhost)", addr)
	}
	return nil
}

func (c Config) arch() syscalls.Arch {
	if c.Arch != "" {
		return c.Arch
	}
	if runtime.GOARCH == "arm64" {
		return syscalls.ArchARM64
	}
	return syscalls.ArchAMD64
}

type Server struct {
	cfg        Config
	collector  ebpf.Collector
	correlator *docker.Correlator
	listener   net.Listener
	listenAddr string

	mu           sync.Mutex
	stopMu       sync.Mutex
	stopping     atomic.Bool
	stopped      bool
	shuttingDown bool
	cachedResp   *StopResponse
	doneCh       chan struct{}
	doneOnce     sync.Once
	shutdownOnce sync.Once
	wg           sync.WaitGroup
}

func NewServer(cfg Config, collector ebpf.Collector, correlator *docker.Correlator) (*Server, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.ControlAddr == "" {
		cfg.ControlAddr = "/run/seccomp-profiler/ctl.sock"
	}
	if cfg.StoppedMarkerPath == "" {
		cfg.StoppedMarkerPath = "/run/seccomp-profiler/stopped"
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = ".seccomp-profiler/profiles"
	}
	if cfg.RawDir == "" {
		cfg.RawDir = ".seccomp-profiler/raw"
	}
	if cfg.LockFile == "" {
		cfg.LockFile = ".seccomp-profiler/lock.json"
	}
	if cfg.CommittedProfile == "" {
		cfg.CommittedProfile = ".seccomp-profiler/profiles/{name}.json"
	}
	if cfg.AllowFile == "" {
		cfg.AllowFile = ".seccomp-profiler/accepted.yml"
	}
	if cfg.BaselineMode == "" {
		cfg.BaselineMode = baseline.ModeStandard
	}
	if cfg.RuntimeMode == "" {
		cfg.RuntimeMode = "auto"
	}
	if cfg.OnChange == "" {
		cfg.OnChange = "report"
	}
	if cfg.FailOn == "" {
		cfg.FailOn = "high-risk"
	}
	if cfg.Arch == "" {
		cfg.Arch = cfg.arch()
	}
	return &Server{
		cfg:        cfg,
		collector:  collector,
		correlator: correlator,
		doneCh:     make(chan struct{}),
	}, nil
}

func (s *Server) Start(ctx context.Context) error {
	network, address := parseControlAddr(s.cfg.ControlAddr)
	if network == "unix" {
		_ = os.MkdirAll(filepath.Dir(address), 0o755)
		_ = os.Remove(address)
	}
	if s.cfg.StoppedMarkerPath != "" {
		_ = os.Remove(s.cfg.StoppedMarkerPath)
	}
	ln, err := listenControl(network, address)
	if err != nil {
		return err
	}
	s.listener = ln
	if network == "tcp" {
		s.listenAddr = "tcp://" + ln.Addr().String()
	} else {
		s.listenAddr = address
	}

	if s.collector != nil {
		eventsCh := s.collector.Events()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				select {
				case ev, ok := <-eventsCh:
					if !ok {
						return
					}
					s.correlator.RecordKernelEvent(ev)
					if ev.Type == ebpf.EventCgroupMkdir && !s.stopping.Load() && s.correlator.IsCgroupContainerDead(ev.CgroupID) {
						s.mu.Lock()
						if !s.stopping.Load() && !s.shuttingDown {
							docker.ReclaimCgroup(s.correlator, s.collector, ev.CgroupID)
						}
						s.mu.Unlock()
					}
				case <-s.doneCh:
					return
				}
			}
		}()
	}

	s.wg.Add(1)
	go s.acceptLoop(ctx)
	return nil
}

func (s *Server) Addr() string {
	return s.listenAddr
}

func (s *Server) Wait() error {
	<-s.doneCh
	s.wg.Wait()
	return nil
}

func (s *Server) closeDone() {
	s.doneOnce.Do(func() { close(s.doneCh) })
}

// shutdown coordinates teardown across STOP and context cancellation so
// listener/collector shutdown runs once and never overlaps an active executeStop.
func (s *Server) shutdown() {
	s.shutdownOnce.Do(func() {
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.stopMu.Lock()
		s.mu.Lock()
		s.shuttingDown = true
		s.mu.Unlock()
		if s.collector != nil {
			_ = s.collector.Close()
		}
		s.stopMu.Unlock()
		s.closeDone()
	})
}

func (s *Server) acceptLoop(ctx context.Context) {
	defer s.wg.Done()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		select {
		case <-ctx.Done():
			// SIGTERM/SIGINT: fully tear down (listener, eBPF programs) so
			// the root daemon never outlives its parent on self-hosted
			// runners.
			s.shutdown()
		case <-s.doneCh:
		}
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	// Untrusted/local clients must not be able to hold control connections
	// open forever (the tcp:// control endpoint has no authentication).
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	sc := bufio.NewScanner(conn)
	if !sc.Scan() {
		return
	}
	cmd := strings.TrimSpace(sc.Text())
	switch cmd {
	case "PING":
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, _ = fmt.Fprintln(conn, `{"ok":true}`)
	case "STOP":
		resp := s.executeStop()
		b, _ := json.Marshal(resp)
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		_, _ = conn.Write(append(b, '\n'))
		_ = conn.Close()
		s.shutdown()
	default:
		_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		b, _ := json.Marshal(StopResponse{OK: false, Error: fmt.Sprintf("unknown command %q", cmd)})
		_, _ = conn.Write(append(b, '\n'))
	}
}

func (s *Server) cacheStopResponse(resp *StopResponse, stopped bool) *StopResponse {
	s.mu.Lock()
	s.cachedResp = resp
	if stopped {
		s.stopped = true
	}
	s.mu.Unlock()
	return resp
}

func (s *Server) executeStop() *StopResponse {
	s.stopMu.Lock()
	defer s.stopMu.Unlock()

	s.mu.Lock()
	if s.stopped && s.cachedResp != nil {
		resp := s.cachedResp
		s.mu.Unlock()
		return resp
	}
	if s.shuttingDown {
		s.mu.Unlock()
		return &StopResponse{OK: false, Error: "daemon shutting down"}
	}
	s.stopping.Store(true)
	s.mu.Unlock()

	var stats map[uint64]ebpf.CgroupStats
	var kernelErrs ebpf.ErrorStats
	if s.collector != nil {
		// 1. Detach programs first so no new map updates race the flush.
		_ = s.collector.Detach()
		// 2. Let the ring buffer drain into the correlator without holding s.mu,
		// so any event-consumer ReclaimCgroup check cannot self-deadlock here.
		events := s.collector.Events()
		deadline := time.Now().Add(2 * time.Second)
		for len(events) > 0 && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(25 * time.Millisecond) // grace for one event in flight
		// 3. Snapshot the maps.
		var err error
		stats, err = s.collector.Flush()
		if err != nil {
			return s.cacheStopResponse(&StopResponse{OK: false, Error: err.Error()}, false)
		}
		errs, err := s.collector.ErrorStats()
		if err != nil {
			return s.cacheStopResponse(&StopResponse{OK: false, Error: fmt.Sprintf("read kernel error stats: %v", err)}, false)
		}
		kernelErrs = errs
	}

	records := s.correlator.BuildRecords(stats)
	rules, err := selector.ParseTargetsInputWithErr(s.cfg.Targets)
	if err != nil {
		return s.cacheStopResponse(&StopResponse{OK: false, Error: fmt.Sprintf("parse targets: %v", err)}, false)
	}
	selCfg := selector.Config{
		Rules:          rules,
		GroupBy:        s.cfg.GroupBy,
		ExtraExcludes:  s.cfg.ExcludeImages,
		ComposeProject: s.cfg.ComposeProject,
	}
	matchedTargets, skipped := selector.Evaluate(selCfg, records)

	approvals, err := diff.LoadApprovals(s.cfg.AllowFile)
	if err != nil {
		return s.cacheStopResponse(&StopResponse{OK: false, Error: fmt.Sprintf("load approvals: %v", err)}, false)
	}

	var builtProfiles []*profile.BuiltProfile
	committedByTarget := make(map[string]*profile.OCISeccompProfile)

	for _, t := range matchedTargets {
		bp, err := profile.Build(t, profile.BuildOptions{
			Arch:             s.cfg.Arch,
			Kernel:           s.cfg.Kernel,
			GeneratorVersion: s.cfg.GeneratorVersion,
			BaselineMode:     s.cfg.BaselineMode,
			RuntimeMode:      s.cfg.RuntimeMode,
			ExtraAllow:       s.cfg.ExtraAllow,
		})
		if err != nil {
			return s.cacheStopResponse(&StopResponse{OK: false, Error: err.Error()}, false)
		}
		builtProfiles = append(builtProfiles, bp)

		commPath := diff.ResolveCommittedProfilePath(s.cfg.CommittedProfile, t.Name, len(matchedTargets))
		if commPath != "" {
			cp, err := profile.LoadOCIProfile(commPath)
			if err != nil && !os.IsNotExist(err) {
				return s.cacheStopResponse(&StopResponse{OK: false, Error: fmt.Sprintf("load committed profile %q: %v", commPath, err)}, false)
			}
			if cp != nil {
				committedByTarget[t.Name] = cp
			}
		}
	}

	var diffs []*diff.TargetDiff
	newCount := 0
	highRiskCount := 0
	now := time.Now().UTC()

	for _, bp := range builtProfiles {
		committed := committedByTarget[bp.TargetName]
		td, err := diff.Compare(bp.TargetName, committed, &bp.OCI, &bp.Raw, approvals, now)
		if err != nil {
			return s.cacheStopResponse(&StopResponse{OK: false, Error: err.Error()}, false)
		}
		diffs = append(diffs, td)
		newCount += len(td.Added)
		for _, a := range td.Added {
			if a.Risk == diff.RiskHigh && !a.Approved {
				highRiskCount++
			}
		}
		for _, e := range td.Escalated {
			if !e.Approved {
				highRiskCount++
			}
		}
		for _, ac := range td.ArgsChangeDetails {
			if !ac.Approved {
				highRiskCount++
			}
		}
		if !s.cfg.Prune {
			// Never auto-remove syscalls or args rules present in the committed baseline.
			profile.MergeCommittedIntoOCI(&bp.OCI, committed)
		}
	}

	// Evaluate baseline drift and security gate BEFORE writing files into
	// WorkingCommitted / OutputDir so WriteTargetFiles never masks PR edits
	// and update-pr never writes committed profiles when the gate fails.
	var driftNotes []string
	if s.cfg.WorkingCommitted != "" && s.cfg.WorkingCommitted != s.cfg.CommittedProfile {
		for _, bp := range builtProfiles {
			base := diff.ResolveCommittedProfilePath(s.cfg.CommittedProfile, bp.TargetName, len(matchedTargets))
			work := diff.ResolveCommittedProfilePath(s.cfg.WorkingCommitted, bp.TargetName, len(matchedTargets))
			if base != "" && work != "" && diff.FileChanged(base, work) {
				driftNotes = append(driftNotes, fmt.Sprintf("committed profile `%s` differs from `%s` in this PR — review carefully (CODEOWNERS + branch protection recommended)", work, base))
			}
		}
	}
	if s.cfg.WorkingAllowFile != "" && s.cfg.WorkingAllowFile != s.cfg.AllowFile && diff.FileChanged(s.cfg.AllowFile, s.cfg.WorkingAllowFile) {
		driftNotes = append(driftNotes, fmt.Sprintf("syscall approvals file `%s` differs from `%s` in this PR — review carefully", s.cfg.WorkingAllowFile, s.cfg.AllowFile))
	}

	gatePassed, gateReason, err := diff.EvaluateGate(diffs, s.cfg.OnChange, s.cfg.FailOn)
	if err != nil {
		return s.cacheStopResponse(&StopResponse{OK: false, Error: err.Error(), GatePassed: false}, false)
	}

	if kernelErrs.Any() {
		summary := fmt.Sprintf("kernel error counters non-zero (%s): some containers or syscalls were not recorded, the generated profile may be incomplete", kernelErrs.String())
		if !strings.EqualFold(strings.TrimSpace(s.cfg.FailOn), "none") {
			gatePassed = false
			gateReason = summary
		}
		driftNotes = append(driftNotes, summary)
	}

	preLock, err := profile.LoadLockHashes(s.cfg.LockFile)
	if err != nil {
		return s.cacheStopResponse(&StopResponse{OK: false, Error: err.Error()}, false)
	}

	writeResults, err := profile.WriteTargetFiles(s.cfg.OutputDir, s.cfg.RawDir, s.cfg.LockFile, builtProfiles)
	if err != nil {
		return s.cacheStopResponse(&StopResponse{OK: false, Error: err.Error()}, false)
	}

	var updatedPaths []string
	if gatePassed && strings.EqualFold(strings.TrimSpace(s.cfg.OnChange), "update-pr") {
		targetCommitted := s.cfg.WorkingCommitted
		if targetCommitted == "" {
			targetCommitted = s.cfg.CommittedProfile
		}
		if targetCommitted != "" {
			updatedPaths, err = profile.SyncCommittedProfiles(targetCommitted, s.cfg.OutputDir, s.cfg.LockFile, writeResults, preLock, builtProfiles)
			if err != nil {
				return s.cacheStopResponse(&StopResponse{OK: false, Error: fmt.Sprintf("update committed profiles: %v", err)}, false)
			}
		}
	}

	md := report.RenderMarkdown(report.SummaryInput{
		Profiles:     builtProfiles,
		WriteResults: writeResults,
		Diffs:        diffs,
		Skipped:      skipped,
		DriftNotes:   driftNotes,
		UpdatedPaths: updatedPaths,
		KernelErrors: kernelErrs,
		Prune:        s.cfg.Prune,
		GatePassed:   gatePassed,
		GateReason:   gateReason,
	})

	resp := &StopResponse{
		OK:               true,
		ProfilesDir:      s.cfg.OutputDir,
		RawDir:           s.cfg.RawDir,
		NewSyscallsCount: newCount,
		HighRiskCount:    highRiskCount,
		GatePassed:       gatePassed,
		GateReason:       gateReason,
		MarkdownSummary:  md,
	}

	if s.cfg.StoppedMarkerPath != "" {
		if b, err := json.Marshal(resp); err == nil {
			_ = writeMarkerAtomic(s.cfg.StoppedMarkerPath, b)
		}
	}

	return s.cacheStopResponse(resp, true)
}

func Ping(addr string) error {
	network, address := parseControlAddr(addr)
	conn, err := dialControl(network, address, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprintln(conn, "PING"); err != nil {
		return err
	}
	var resp struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("daemon returned ok=false")
	}
	return nil
}

func writeMarkerAtomic(path string, data []byte) error {
	return profile.WriteFileAtomicNoSymlink(path, data, false)
}

func Stop(addr string, stoppedMarkerPath string) (*StopResponse, error) {
	network, address := parseControlAddr(addr)
	conn, err := dialControl(network, address, 5*time.Second)
	if err != nil {
		// Fall back to the stopped marker only after confirming the live
		// daemon is unreachable (e.g. second idempotent stop from post hook).
		if stoppedMarkerPath != "" {
			if data, readErr := profile.ReadFileNoSymlink(stoppedMarkerPath); readErr == nil && len(data) > 0 {
				var cached StopResponse
				if jsonErr := json.Unmarshal(data, &cached); jsonErr == nil && cached.OK {
					return &cached, nil
				}
			}
		}
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := fmt.Fprintln(conn, "STOP"); err != nil {
		return nil, err
	}
	var resp StopResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return &resp, fmt.Errorf("daemon stop error: %s", resp.Error)
	}
	return &resp, nil
}

func parseControlAddr(addr string) (string, string) {
	if strings.HasPrefix(addr, "tcp://") {
		return "tcp", strings.TrimPrefix(addr, "tcp://")
	}
	return "unix", strings.TrimPrefix(addr, "unix://")
}
