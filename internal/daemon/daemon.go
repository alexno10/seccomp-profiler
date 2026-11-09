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
	AllowFile         string
	Targets           string
	GroupBy           string
	ExcludeImages     []string
	BaselineMode      baseline.Mode
	RuntimeMode       string
	ExtraAllow        []string
	OnChange          string
	FailOn            string
	Arch              syscalls.Arch
	Kernel            string
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

type Server struct {
	cfg        Config
	collector  ebpf.Collector
	correlator *docker.Correlator
	listener   net.Listener
	listenAddr string

	mu         sync.Mutex
	stopped    bool
	cachedResp *StopResponse
	doneCh     chan struct{}
	eventsDone chan struct{}
}

func NewServer(cfg Config, collector ebpf.Collector, correlator *docker.Correlator) *Server {
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
		if runtime.GOARCH == "arm64" {
			cfg.Arch = syscalls.ArchARM64
		} else {
			cfg.Arch = syscalls.ArchAMD64
		}
	}
	return &Server{
		cfg:        cfg,
		collector:  collector,
		correlator: correlator,
		doneCh:     make(chan struct{}),
	}
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
		s.eventsDone = make(chan struct{})
		go func() {
			defer close(s.eventsDone)
			for ev := range s.collector.Events() {
				s.correlator.RecordKernelEvent(ev)
			}
		}()
	}

	go s.acceptLoop(ctx)
	return nil
}

func (s *Server) Addr() string {
	return s.listenAddr
}

func (s *Server) Wait() error {
	<-s.doneCh
	return nil
}

func (s *Server) acceptLoop(ctx context.Context) {
	go func() {
		select {
		case <-ctx.Done():
			_ = s.listener.Close()
		case <-s.doneCh:
		}
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	if !sc.Scan() {
		return
	}
	cmd := strings.TrimSpace(sc.Text())
	switch cmd {
	case "PING":
		_, _ = fmt.Fprintln(conn, `{"ok":true}`)
	case "STOP":
		resp := s.executeStop()
		b, _ := json.Marshal(resp)
		_, _ = conn.Write(append(b, '\n'))
		go func() {
			time.Sleep(50 * time.Millisecond)
			_ = s.listener.Close()
			if s.collector != nil {
				_ = s.collector.Close()
			}
			s.mu.Lock()
			select {
			case <-s.doneCh:
			default:
				close(s.doneCh)
			}
			s.mu.Unlock()
		}()
	default:
		_, _ = fmt.Fprintf(conn, `{"ok":false,"error":"unknown command %q"}`+"\n", cmd)
	}
}

func (s *Server) executeStop() *StopResponse {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped && s.cachedResp != nil {
		return s.cachedResp
	}

	var stats map[uint64]ebpf.CgroupStats
	if s.collector != nil {
		var err error
		stats, err = s.collector.Flush()
		if err != nil {
			resp := &StopResponse{OK: false, Error: err.Error()}
			s.cachedResp = resp
			return resp
		}
		if s.eventsDone != nil {
			select {
			case <-s.eventsDone:
			case <-time.After(50 * time.Millisecond):
			}
		}
	}

	records := s.correlator.BuildRecords(stats)
	selCfg := selector.Config{
		Rules:         selector.ParseTargetsInput(s.cfg.Targets),
		GroupBy:       s.cfg.GroupBy,
		ExtraExcludes: s.cfg.ExcludeImages,
	}
	matchedTargets, skipped := selector.Evaluate(selCfg, records)

	approvals, err := diff.LoadApprovals(s.cfg.AllowFile)
	if err != nil {
		resp := &StopResponse{OK: false, Error: fmt.Sprintf("load approvals: %v", err)}
		s.cachedResp = resp
		return resp
	}

	var builtProfiles []*profile.BuiltProfile
	committedByTarget := make(map[string]*profile.OCISeccompProfile)

	for _, t := range matchedTargets {
		bp, err := profile.Build(t, profile.BuildOptions{
			Arch:         s.cfg.Arch,
			Kernel:       s.cfg.Kernel,
			BaselineMode: s.cfg.BaselineMode,
			RuntimeMode:  s.cfg.RuntimeMode,
			ExtraAllow:   s.cfg.ExtraAllow,
		})
		if err != nil {
			resp := &StopResponse{OK: false, Error: err.Error()}
			s.cachedResp = resp
			return resp
		}
		builtProfiles = append(builtProfiles, bp)

		commPath := diff.ResolveCommittedProfilePath(s.cfg.CommittedProfile, t.Name, len(matchedTargets))
		if commPath != "" {
			cp, err := profile.LoadOCIProfile(commPath)
			if err != nil && !os.IsNotExist(err) {
				resp := &StopResponse{OK: false, Error: fmt.Sprintf("load committed profile %q: %v", commPath, err)}
				s.cachedResp = resp
				return resp
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
			resp := &StopResponse{OK: false, Error: err.Error()}
			s.cachedResp = resp
			return resp
		}
		diffs = append(diffs, td)
		newCount += len(td.Added)
		for _, a := range td.Added {
			if a.Risk == diff.RiskHigh && !a.Approved {
				highRiskCount++
			}
		}
		// Never auto-remove syscalls or args rules present in the committed baseline.
		profile.MergeCommittedIntoOCI(&bp.OCI, committed)
	}

	writeResults, err := profile.WriteTargetFiles(s.cfg.OutputDir, s.cfg.RawDir, s.cfg.LockFile, builtProfiles)
	if err != nil {
		resp := &StopResponse{OK: false, Error: err.Error()}
		s.cachedResp = resp
		return resp
	}

	gatePassed, gateReason, err := diff.EvaluateGate(diffs, s.cfg.OnChange, s.cfg.FailOn)
	if err != nil {
		resp := &StopResponse{OK: false, Error: err.Error(), GatePassed: false}
		s.cachedResp = resp
		return resp
	}

	md := report.RenderMarkdown(report.SummaryInput{
		Profiles:     builtProfiles,
		WriteResults: writeResults,
		Diffs:        diffs,
		Skipped:      skipped,
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
		_ = os.MkdirAll(filepath.Dir(s.cfg.StoppedMarkerPath), 0o755)
		if b, err := json.Marshal(resp); err == nil {
			_ = os.WriteFile(s.cfg.StoppedMarkerPath, b, 0o644)
		}
	}

	s.stopped = true
	s.cachedResp = resp
	return resp
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

func Stop(addr string, stoppedMarkerPath string) (*StopResponse, error) {
	if stoppedMarkerPath != "" {
		if data, err := os.ReadFile(stoppedMarkerPath); err == nil && len(data) > 0 {
			var cached StopResponse
			if err := json.Unmarshal(data, &cached); err == nil && cached.OK {
				return &cached, nil
			}
		}
	}

	network, address := parseControlAddr(addr)
	conn, err := dialControl(network, address, 5*time.Second)
	if err != nil {
		if stoppedMarkerPath != "" {
			if data, readErr := os.ReadFile(stoppedMarkerPath); readErr == nil && len(data) > 0 {
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

var (
	inprocMu        sync.Mutex
	inprocListeners = make(map[string]*pipeListener)
)

type pipeAddr string

func (p pipeAddr) Network() string { return "pipe" }
func (p pipeAddr) String() string  { return string(p) }

type pipeListener struct {
	addr   string
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		inprocMu.Lock()
		delete(inprocListeners, l.addr)
		inprocMu.Unlock()
	})
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr(l.addr) }

func listenControl(network, address string) (net.Listener, error) {
	ln, err := net.Listen(network, address)
	if err == nil {
		return ln, nil
	}
	if runtime.GOOS != "windows" {
		return nil, err
	}
	// Fallback to in-process net.Pipe listener when Windows AppContainer sandbox blocks WinSock creation.
	pl := &pipeListener{
		addr:   address,
		ch:     make(chan net.Conn, 16),
		closed: make(chan struct{}),
	}
	inprocMu.Lock()
	inprocListeners[address] = pl
	inprocMu.Unlock()
	return pl, nil
}

func dialControl(network, address string, timeout time.Duration) (net.Conn, error) {
	inprocMu.Lock()
	pl, ok := inprocListeners[address]
	inprocMu.Unlock()
	if ok {
		c1, c2 := net.Pipe()
		select {
		case pl.ch <- c1:
			return c2, nil
		case <-pl.closed:
			_ = c1.Close()
			_ = c2.Close()
			return nil, net.ErrClosed
		}
	}
	return net.DialTimeout(network, address, timeout)
}
