package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/baseline"
	"github.com/alexno10/seccomp-profiler/internal/daemon"
	"github.com/alexno10/seccomp-profiler/internal/diff"
	"github.com/alexno10/seccomp-profiler/internal/docker"
	"github.com/alexno10/seccomp-profiler/internal/ebpf"
	"github.com/alexno10/seccomp-profiler/internal/profile"
	"github.com/alexno10/seccomp-profiler/internal/report"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "version", "--version", "-v":
		fmt.Println(version)
	case "daemon", "start":
		if err := runDaemon(args); err != nil {
			fmt.Fprintf(os.Stderr, "seccomp-profiler daemon error: %v\n", err)
			os.Exit(1)
		}
	case "ping":
		if err := runPing(args); err != nil {
			fmt.Fprintf(os.Stderr, "seccomp-profiler ping error: %v\n", err)
			os.Exit(1)
		}
	case "stop":
		if err := runStop(args); err != nil {
			fmt.Fprintf(os.Stderr, "seccomp-profiler stop error: %v\n", err)
			os.Exit(1)
		}
	case "diff":
		if err := runDiff(args); err != nil {
			fmt.Fprintf(os.Stderr, "seccomp-profiler diff error: %v\n", err)
			os.Exit(1)
		}
	case "merge":
		if err := runMerge(args); err != nil {
			fmt.Fprintf(os.Stderr, "seccomp-profiler merge error: %v\n", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: seccomp-profiler <daemon|start|ping|stop|diff|merge|version> [flags]\n")
}

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	sock := fs.String("socket", "/run/seccomp-profiler/ctl.sock", "Control socket path")
	marker := fs.String("stopped-marker", "/run/seccomp-profiler/stopped", "Stopped marker file path")
	bpfObj := fs.String("bpf-obj", "", "Path to compiled profiler.bpf.o")
	outDir := fs.String("output-dir", ".seccomp-profiler/profiles", "Output directory for profiles")
	rawDir := fs.String("raw-dir", ".seccomp-profiler/raw", "Output directory for raw v1 profiles")
	lockFile := fs.String("lock-file", ".seccomp-profiler/lock.json", "Lock file path")
	committed := fs.String("committed-profile", ".seccomp-profiler/profiles/{name}.json", "Committed profile path/template")
	allowFile := fs.String("allow-file", ".seccomp-profiler/accepted.yml", "Approvals file path")
	targets := fs.String("targets", "", "Target selector rules")
	groupBy := fs.String("group-by", "auto", "Grouping mode")
	excludes := fs.String("exclude-images", "", "Extra image globs to exclude")
	baseMode := fs.String("baseline", "standard", "Baseline mode (none|minimal|standard)")
	rtMode := fs.String("runtime", "auto", "Runtime mode (auto|go|java|node|python|none)")
	extraAllow := fs.String("extra-allow", "", "Additional allowed syscalls")
	onChange := fs.String("on-change", "report", "Policy on profile change (report|fail)")
	failOn := fs.String("fail-on", "high-risk", "Security gate policy (none|high-risk|any-new)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	collector, err := ebpf.NewCollector(*bpfObj)
	if err != nil {
		return err
	}
	defer collector.Close()

	corr := docker.NewCorrelator(nil)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Pre-scan already-running containers before signaling readiness.
	if runningEvents, inodes, err := docker.ScanRunningContainers(ctx); err == nil {
		for _, ev := range runningEvents {
			corr.RecordDockerEvent(ev)
		}
		for cid, ino := range inodes {
			corr.BindCgroup(ino, cid)
			_ = collector.TrackCgroup(ino)
		}
	}

	go func() {
		_ = docker.StreamDockerEvents(ctx, func(ev docker.DockerEvent) {
			corr.RecordDockerEvent(ev)
		})
	}()

	cfg := daemon.Config{
		ControlAddr:       *sock,
		StoppedMarkerPath: *marker,
		OutputDir:         *outDir,
		RawDir:            *rawDir,
		LockFile:          *lockFile,
		CommittedProfile:  *committed,
		AllowFile:         *allowFile,
		Targets:           *targets,
		GroupBy:           *groupBy,
		ExcludeImages:     splitLines(*excludes),
		BaselineMode:      baseline.Mode(*baseMode),
		RuntimeMode:       *rtMode,
		ExtraAllow:        splitLines(*extraAllow),
		OnChange:          *onChange,
		FailOn:            *failOn,
	}

	srv := daemon.NewServer(cfg, collector, corr)
	if err := srv.Start(ctx); err != nil {
		return err
	}
	return srv.Wait()
}

func runPing(args []string) error {
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
	sock := fs.String("socket", "/run/seccomp-profiler/ctl.sock", "Control socket path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return daemon.Ping(*sock)
}

func runStop(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	sock := fs.String("socket", "/run/seccomp-profiler/ctl.sock", "Control socket path")
	marker := fs.String("stopped-marker", "/run/seccomp-profiler/stopped", "Stopped marker file path")
	jsonOut := fs.Bool("json", false, "Output JSON response")
	if err := fs.Parse(args); err != nil {
		return err
	}
	resp, err := daemon.Stop(*sock, *marker)
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		return enc.Encode(resp)
	}
	fmt.Print(resp.MarkdownSummary)
	if !resp.GatePassed {
		return fmt.Errorf("security gate failed: %s", resp.GateReason)
	}
	return nil
}

func runDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	target := fs.String("target", "default", "Target name")
	committedPath := fs.String("committed", "", "Committed seccomp.json path")
	currentPath := fs.String("current", "", "Current seccomp.json path")
	allowFile := fs.String("allow-file", ".seccomp-profiler/accepted.yml", "Approvals file path")
	onChange := fs.String("on-change", "report", "on-change policy (report|fail)")
	failOn := fs.String("fail-on", "high-risk", "fail-on policy (none|high-risk|any-new)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *currentPath == "" {
		return fmt.Errorf("--current is required")
	}
	curr, err := profile.LoadOCIProfile(*currentPath)
	if err != nil {
		return err
	}
	var comm *profile.OCISeccompProfile
	if *committedPath != "" {
		c, err := profile.LoadOCIProfile(*committedPath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("load committed profile %q: %w", *committedPath, err)
		}
		comm = c
	}
	approvals, err := diff.LoadApprovals(*allowFile)
	if err != nil {
		return err
	}
	tName := *target
	if tName == "default" {
		tName = strings.TrimSuffix(filepath.Base(*currentPath), ".json")
	}
	td, err := diff.Compare(tName, comm, curr, nil, approvals, time.Now().UTC())
	if err != nil {
		return err
	}
	passed, reason, err := diff.EvaluateGate([]*diff.TargetDiff{td}, *onChange, *failOn)
	if err != nil {
		return err
	}
	md := report.RenderMarkdown(report.SummaryInput{
		Diffs:      []*diff.TargetDiff{td},
		GatePassed: passed,
		GateReason: reason,
	})
	fmt.Print(md)
	if !passed {
		return fmt.Errorf("security gate failed: %s", reason)
	}
	return nil
}

func runMerge(args []string) error {
	fs := flag.NewFlagSet("merge", flag.ContinueOnError)
	inputDir := fs.String("input-dir", "", "Directory containing .profile.v1.json shards (searched recursively)")
	outDir := fs.String("output-dir", ".seccomp-profiler/profiles", "Output directory for merged profiles")
	rawDir := fs.String("raw-dir", ".seccomp-profiler/raw", "Output directory for merged raw v1 profiles")
	lockFile := fs.String("lock-file", ".seccomp-profiler/lock.json", "Lock file path")
	committedPattern := fs.String("committed-profile", ".seccomp-profiler/profiles/{name}.json", "Committed profile path/template")
	allowFile := fs.String("allow-file", ".seccomp-profiler/accepted.yml", "Approvals file path")
	onChange := fs.String("on-change", "report", "on-change policy (report|fail|update-pr)")
	failOn := fs.String("fail-on", "high-risk", "fail-on policy (none|high-risk|any-new)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var rawPaths []string
	collectFromPath := func(p string) error {
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			rawPaths = append(rawPaths, p)
			return nil
		}
		return filepath.WalkDir(p, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !d.IsDir() && strings.HasSuffix(d.Name(), ".profile.v1.json") {
				rawPaths = append(rawPaths, path)
			}
			return nil
		})
	}

	if *inputDir != "" {
		if err := collectFromPath(*inputDir); err != nil {
			return err
		}
	}
	for _, arg := range fs.Args() {
		if err := collectFromPath(arg); err != nil {
			return err
		}
	}
	if len(rawPaths) == 0 {
		return fmt.Errorf("no .profile.v1.json input files provided (use --input-dir or pass file paths)")
	}

	var raws []*profile.RawProfileV1
	for _, p := range rawPaths {
		r, err := profile.LoadRawProfileV1(p)
		if err != nil {
			return err
		}
		raws = append(raws, r)
	}

	now := time.Now().UTC()
	built, err := profile.MergeRawProfiles(raws, now, version)
	if err != nil {
		return err
	}
	approvals, err := diff.LoadApprovals(*allowFile)
	if err != nil {
		return err
	}

	var diffs []*diff.TargetDiff
	for _, b := range built {
		commPath := diff.ResolveCommittedProfilePath(*committedPattern, b.TargetName, len(built))
		var comm *profile.OCISeccompProfile
		if commPath != "" {
			if c, loadErr := profile.LoadOCIProfile(commPath); loadErr == nil {
				comm = c
			}
		}
		td, cmpErr := diff.Compare(b.TargetName, comm, &b.OCI, &b.Raw, approvals, now)
		if cmpErr != nil {
			return cmpErr
		}
		if comm != nil {
			profile.MergeCommittedIntoOCI(&b.OCI, comm)
		}
		diffs = append(diffs, td)
	}

	writeRes, err := profile.WriteTargetFiles(*outDir, *rawDir, *lockFile, built)
	if err != nil {
		return err
	}
	passed, reason, err := diff.EvaluateGate(diffs, *onChange, *failOn)
	if err != nil {
		return err
	}
	md := report.RenderMarkdown(report.SummaryInput{
		Profiles:     built,
		WriteResults: writeRes,
		Diffs:        diffs,
		GatePassed:   passed,
		GateReason:   reason,
	})
	fmt.Print(md)
	if !passed {
		return fmt.Errorf("security gate failed: %s", reason)
	}
	return nil
}

func splitLines(s string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ','
	}) {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}
