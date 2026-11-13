package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/ebpf"
	"github.com/alexno10/seccomp-profiler/internal/selector"
)

const dockerInspectTimeout = 2 * time.Second

// ephemeralEventAttrs are Docker event Actor attributes that describe the
// event rather than the container (exitCode, execID, ...). They must not leak
// into labels, raw artifacts, or target selection.
var ephemeralEventAttrs = map[string]bool{
	"exitCode":     true,
	"execID":       true,
	"execDuration": true,
	"signal":       true,
	"status":       true,
}

type DockerEvent struct {
	Action      string
	ID          string
	Image       string
	Name        string
	Labels      map[string]string
	TimeNano    int64
	Preexisting bool
}

type InodeResolver func(containerID string) (uint64, error)

type containerMeta struct {
	id          string
	name        string
	image       string
	labels      map[string]string
	startNano   int64
	endNano     int64
	preexisting bool
	dead        bool
}

type Correlator struct {
	mu           sync.Mutex
	resolver     InodeResolver
	containers   map[string]*containerMeta
	cgroupToCID  map[uint64]string
	cidToCgroups map[string][]uint64
	cgroupBins   map[uint64][]string
	deadStats    map[uint64]ebpf.CgroupStats
}

func NewCorrelator(resolver InodeResolver) *Correlator {
	if resolver == nil {
		resolver = DefaultResolveContainerCgroupInode
	}
	return &Correlator{
		resolver:     resolver,
		containers:   make(map[string]*containerMeta),
		cgroupToCID:  make(map[uint64]string),
		cidToCgroups: make(map[string][]uint64),
		cgroupBins:   make(map[uint64][]string),
		deadStats:    make(map[uint64]ebpf.CgroupStats),
	}
}

// ExtractContainerID returns the innermost (last) exact 64-hex container ID
// in cgroupPath so nested DinD paths match the child container rather than the
// outer DinD host container.
func ExtractContainerID(cgroupPath string) (string, bool) {
	s := strings.ToLower(cgroupPath)
	var last string
	start := -1
	for i := 0; i <= len(s); i++ {
		isHex := i < len(s) && ((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))
		if isHex {
			if start == -1 {
				start = i
			}
			continue
		}
		if start != -1 {
			if i-start == 64 {
				last = s[start:i]
			}
			start = -1
		}
	}
	if last == "" {
		return "", false
	}
	return last, true
}

func (c *Correlator) RecordDockerEvent(ev DockerEvent) {
	if ev.ID == "" {
		return
	}
	var resolveID string

	c.mu.Lock()
	meta, ok := c.containers[ev.ID]
	if !ok {
		meta = &containerMeta{
			id:     ev.ID,
			labels: make(map[string]string),
		}
		c.containers[ev.ID] = meta
	}
	if ev.Preexisting {
		meta.preexisting = true
	}
	if ev.Image != "" {
		meta.image = ev.Image
	}
	if ev.Name != "" {
		meta.name = ev.Name
	}
	for k, v := range ev.Labels {
		if ephemeralEventAttrs[k] {
			continue
		}
		if k == "image" && meta.image == "" {
			meta.image = v
			continue
		}
		if k == "name" && meta.name == "" {
			meta.name = v
			continue
		}
		meta.labels[k] = v
	}
	switch ev.Action {
	case "create":
		if meta.startNano == 0 && ev.TimeNano > 0 {
			meta.startNano = ev.TimeNano
		}
	case "start":
		// Reset endNano/dead only on a genuine (re)start newer than any recorded end,
		// so out-of-order or pre-existing start events do not resurrect dead containers.
		if ev.TimeNano > 0 && (meta.endNano == 0 || ev.TimeNano > meta.endNano) {
			meta.startNano = ev.TimeNano
			meta.endNano = 0
			meta.dead = false
		}
		if len(c.cidToCgroups[ev.ID]) == 0 {
			resolveID = ev.ID
		}
	case "die", "stop", "destroy":
		if ev.Action == "die" || ev.Action == "destroy" {
			meta.dead = true
		}
		if ev.TimeNano > 0 && meta.endNano == 0 {
			meta.endNano = ev.TimeNano
		}
	}
	c.mu.Unlock()

	if resolveID != "" && c.resolver != nil {
		if ino, err := c.resolver(resolveID); err == nil && ino != 0 {
			c.BindCgroup(ino, resolveID)
		}
	}
}

// IsCgroupContainerDead reports whether cgID is bound to a container that has
// already emitted a die or destroy event.
func (c *Correlator) IsCgroupContainerDead(cgID uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	cid := c.cgroupToCID[cgID]
	if cid == "" {
		return false
	}
	meta := c.containers[cid]
	return meta != nil && meta.dead
}

// ReclaimCgroup flushes any recorded stats for cgID into corr and removes the
// cgroup entry from the kernel eBPF maps.
func ReclaimCgroup(corr *Correlator, collector ebpf.Collector, cgID uint64) {
	if corr == nil || collector == nil || cgID == 0 {
		return
	}
	if st, ok, err := collector.FlushCgroup(cgID); err == nil && ok {
		corr.RecordDeadStats(cgID, st)
	}
	_ = collector.DeleteCgroup(cgID)
}

func (c *Correlator) BindCgroup(cgroupID uint64, containerID string) {
	if cgroupID == 0 || containerID == "" {
		return
	}
	c.mu.Lock()
	c.cgroupToCID[cgroupID] = containerID
	c.cidToCgroups[containerID] = appendIfMissing(c.cidToCgroups[containerID], cgroupID)
	c.mu.Unlock()
}

// CgroupsForContainer returns all cgroup inodes bound to a container so the
// daemon can drain and delete their BPF map entries when the container dies.
func (c *Correlator) CgroupsForContainer(containerID string) []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]uint64, len(c.cidToCgroups[containerID]))
	copy(out, c.cidToCgroups[containerID])
	return out
}

// RecordDeadStats stores a final snapshot of a cgroup's syscall counters. The
// daemon flushes and deletes the BPF map entry when a container dies; without
// this the stats would be lost before Stop.
func (c *Correlator) RecordDeadStats(cgroupID uint64, stats ebpf.CgroupStats) {
	if cgroupID == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadStats[cgroupID] = stats
}

// DrainDeadStats returns and clears all accumulated dead-cgroup stats.
func (c *Correlator) DrainDeadStats() map[uint64]ebpf.CgroupStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.deadStats
	c.deadStats = make(map[uint64]ebpf.CgroupStats)
	return out
}

func (c *Correlator) RecordKernelEvent(ev ebpf.KernelEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ev.CgroupPath != "" {
		if cid, ok := ExtractContainerID(ev.CgroupPath); ok {
			c.cgroupToCID[ev.CgroupID] = cid
			c.cidToCgroups[cid] = appendIfMissing(c.cidToCgroups[cid], ev.CgroupID)
		}
	}
	if ev.ExecFilename != "" {
		c.cgroupBins[ev.CgroupID] = append(c.cgroupBins[ev.CgroupID], ev.ExecFilename)
	}
}

func (c *Correlator) BuildRecords(stats map[uint64]ebpf.CgroupStats) []selector.ContainerRecord {
	c.mu.Lock()
	defer c.mu.Unlock()

	byCID := make(map[string]*selector.ContainerRecord)

	merge := func(cgID uint64, st ebpf.CgroupStats) {
		cid := c.cgroupToCID[cgID]
		if cid == "" {
			return
		}
		rec, ok := byCID[cid]
		if !ok {
			meta := c.containers[cid]
			rec = &selector.ContainerRecord{
				ID:          cid,
				SyscallHits: make(map[int]uint32),
				Labels:      make(map[string]string),
			}
			if meta != nil {
				rec.Name = meta.name
				rec.Image = meta.image
				rec.Preexisting = meta.preexisting
				for k, v := range meta.labels {
					rec.Labels[k] = v
				}
				if meta.startNano > 0 && meta.endNano >= meta.startNano {
					rec.DurationMs = (meta.endNano - meta.startNano) / 1_000_000
				}
			}
			if rec.Image == "" {
				if len(cid) >= 12 {
					rec.Image = cid[:12]
				} else {
					rec.Image = cid
				}
			}
			byCID[cid] = rec
		}
		rec.CompatHits += st.CompatCount
		rec.ExecutedBins = append(rec.ExecutedBins, c.cgroupBins[cgID]...)
		for nr, count := range st.Counts {
			if count > 0 {
				rec.SyscallHits[nr] += count
			}
		}
	}

	for cgID, st := range stats {
		merge(cgID, st)
	}
	// Dead containers whose BPF entries were already deleted still count.
	for cgID, st := range c.deadStats {
		if _, live := stats[cgID]; live {
			continue
		}
		merge(cgID, st)
	}

	var out []selector.ContainerRecord
	for _, r := range byCID {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

func appendIfMissing(list []uint64, v uint64) []uint64 {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

type rawDockerEventJSON struct {
	Status   string `json:"status"`
	Action   string `json:"Action"`
	ID       string `json:"id"`
	From     string `json:"from"`
	TimeNano int64  `json:"timeNano"`
	Actor    struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
}

func ParseDockerEventJSON(line []byte) (DockerEvent, error) {
	var raw rawDockerEventJSON
	if err := json.Unmarshal(line, &raw); err != nil {
		return DockerEvent{}, err
	}
	action := raw.Action
	if action == "" {
		action = raw.Status
	}
	if idx := strings.IndexByte(action, ':'); idx != -1 {
		action = strings.TrimSpace(action[:idx])
	}
	id := raw.Actor.ID
	if id == "" {
		id = raw.ID
	}
	image := raw.From
	if imgAttr := raw.Actor.Attributes["image"]; imgAttr != "" {
		image = imgAttr
	}
	name := raw.Actor.Attributes["name"]
	labels := make(map[string]string)
	for k, v := range raw.Actor.Attributes {
		if k == "image" || k == "name" || ephemeralEventAttrs[k] {
			continue
		}
		labels[k] = v
	}
	return DockerEvent{
		Action:   action,
		ID:       id,
		Image:    image,
		Name:     name,
		Labels:   labels,
		TimeNano: raw.TimeNano,
	}, nil
}

type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.max <= 0 {
		return len(p), nil
	}
	rem := b.max - b.buf.Len()
	if rem > 0 {
		if len(p) > rem {
			_, _ = b.buf.Write(p[:rem])
		} else {
			_, _ = b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	return strings.TrimSpace(b.buf.String())
}

// NewDockerEventStreamer returns a StreamDockerEvents-compatible function that
// remembers the timestamp of the last observed event across reconnects.
func NewDockerEventStreamer() func(context.Context, func(DockerEvent)) error {
	var mu sync.Mutex
	since := time.Now().Add(-5 * time.Second)
	return func(ctx context.Context, onEvent func(DockerEvent)) error {
		mu.Lock()
		curSince := since
		mu.Unlock()
		return streamDockerEventsSince(ctx, curSince, func(ev DockerEvent) {
			if ev.TimeNano > 0 {
				t := time.Unix(0, ev.TimeNano)
				mu.Lock()
				if t.After(since) {
					since = t
				}
				mu.Unlock()
			}
			if onEvent != nil {
				onEvent(ev)
			}
		})
	}
}

func StreamDockerEvents(ctx context.Context, onEvent func(DockerEvent)) error {
	return streamDockerEventsSince(ctx, time.Now().Add(-5*time.Second), onEvent)
}

func streamDockerEventsSince(ctx context.Context, sinceTime time.Time, onEvent func(DockerEvent)) error {
	since := fmt.Sprintf("%d", sinceTime.Unix())
	cmd := exec.CommandContext(ctx, "docker", "events", "--since", since, "--filter", "type=container", "--format", "{{json .}}")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr := &limitedBuffer{max: 4096}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	return readDockerEventStream(ctx, stdout, onEvent, func() error {
		err := cmd.Wait()
		if err != nil && stderr.String() != "" {
			return fmt.Errorf("%w: %s", err, stderr.String())
		}
		return err
	})
}

func readDockerEventStream(ctx context.Context, r io.Reader, onEvent func(DockerEvent), waitFn func() error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		ev, err := ParseDockerEventJSON(sc.Bytes())
		if err == nil && ev.ID != "" && onEvent != nil {
			onEvent(ev)
		}
	}
	scanErr := sc.Err()
	var waitErr error
	if waitFn != nil {
		waitErr = waitFn()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if scanErr != nil {
		return fmt.Errorf("read docker events stream: %w", scanErr)
	}
	if waitErr != nil {
		return fmt.Errorf("docker events exited: %w", waitErr)
	}
	return nil
}

type dockerInspectContainer struct {
	Id     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

func defaultDockerCmdRunner(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "docker", args...).Output()
}

func isContainerNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "no such object") || strings.Contains(s, "no such container") || strings.Contains(s, "not found")
}

// ScanRunningContainers inspects containers that are already running when the
// profiler starts. Pre-existing containers are marked so profiles can flag
// them as partial (their early syscalls were never observed).
func ScanRunningContainers(ctx context.Context) ([]DockerEvent, map[string]uint64, error) {
	return scanRunningContainersWithRunner(ctx, defaultDockerCmdRunner, DefaultResolveContainerCgroupInode)
}

func scanRunningContainersWithRunner(
	ctx context.Context,
	runCmd func(context.Context, ...string) ([]byte, error),
	resolveFn InodeResolver,
) ([]DockerEvent, map[string]uint64, error) {
	out, err := runCmd(ctx, "ps", "-q", "--no-trunc")
	if err != nil {
		return nil, nil, err
	}
	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if cid := strings.TrimSpace(line); cid != "" && !strings.HasPrefix(cid, "-") {
			ids = append(ids, cid)
		}
	}
	if len(ids) == 0 {
		return nil, map[string]uint64{}, nil
	}

	var inspected []dockerInspectContainer
	// Try one batched inspect first; if a short-lived container vanished mid-batch,
	// fall back to inspecting each ID individually so surviving containers remain tracked.
	inspOut, batchErr := runCmd(ctx, append([]string{"inspect", "--"}, ids...)...)
	if batchErr == nil {
		if err := json.Unmarshal(inspOut, &inspected); err != nil {
			return nil, nil, err
		}
	} else {
		var lastErr error
		allNotFound := true
		for _, id := range ids {
			singleOut, singleErr := runCmd(ctx, "inspect", "--", id)
			if singleErr != nil {
				lastErr = singleErr
				if !isContainerNotFoundErr(singleErr) {
					allNotFound = false
				}
				continue
			}
			var one []dockerInspectContainer
			if uErr := json.Unmarshal(singleOut, &one); uErr != nil {
				return nil, nil, uErr
			}
			inspected = append(inspected, one...)
		}
		if len(inspected) == 0 && !allNotFound && lastErr != nil {
			return nil, nil, lastErr
		}
	}

	var events []DockerEvent
	inodes := make(map[string]uint64)
	for _, item := range inspected {
		events = append(events, DockerEvent{
			Action:      "start",
			ID:          item.Id,
			Image:       item.Config.Image,
			Name:        strings.TrimPrefix(item.Name, "/"),
			Labels:      item.Config.Labels,
			Preexisting: true,
		})
		if resolveFn != nil {
			if ino, err := resolveFn(item.Id); err == nil && ino != 0 {
				inodes[item.Id] = ino
			}
		}
	}
	return events, inodes, nil
}

func runDockerInspectPID(ctx context.Context, containerID string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Pid}}", "--", containerID).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytes.TrimSpace(out))), nil
}

func isASCIIAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func DefaultResolveContainerCgroupInode(containerID string) (uint64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dockerInspectTimeout)
	defer cancel()
	return resolveContainerCgroupInode(ctx, "/sys/fs/cgroup", "/proc", containerID, runDockerInspectPID, statInode)
}

func resolveContainerCgroupInode(
	ctx context.Context,
	cgroupRoot string,
	procRoot string,
	containerID string,
	inspectPIDFn func(context.Context, string) (string, error),
	statFn func(string) (uint64, error),
) (uint64, error) {
	if containerID == "" || strings.HasPrefix(containerID, "-") || statFn == nil {
		return 0, os.ErrNotExist
	}
	candidates := []string{
		filepath.Join(cgroupRoot, "system.slice", fmt.Sprintf("docker-%s.scope", containerID)),
		filepath.Join(cgroupRoot, "docker", containerID),
	}
	for _, p := range candidates {
		if ino, err := statFn(p); err == nil && ino != 0 {
			return ino, nil
		}
	}
	if inspectPIDFn != nil {
		pid, err := inspectPIDFn(ctx, containerID)
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if err == nil && isASCIIAllDigits(pid) && pid != "0" {
			if cgBytes, err := os.ReadFile(filepath.Join(procRoot, pid, "cgroup")); err == nil {
				if ino, err := resolveContainerCgroupInodeFromProc(cgroupRoot, cgBytes, containerID, statFn); err == nil && ino != 0 {
					return ino, nil
				}
			}
		}
	}
	return findCgroupDirByContainerID(cgroupRoot, containerID, statFn)
}

func resolveContainerCgroupInodeFromProc(
	cgroupRoot string,
	cgBytes []byte,
	containerID string,
	statFn func(string) (uint64, error),
) (uint64, error) {
	cidLower := strings.ToLower(containerID)
	if cidLower == "" || statFn == nil {
		return 0, os.ErrNotExist
	}
	cleanRoot := filepath.Clean(cgroupRoot)
	var v2Paths, v1Paths []string
	for _, rawLine := range strings.Split(string(cgBytes), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		rel := strings.TrimPrefix(parts[2], "/")
		// Reject host root "/" and path traversals, and verify container ID match
		// so DinD PID namespace collisions never bind an unrelated host cgroup.
		if rel == "" || rel == "." || strings.Contains(rel, "..") {
			continue
		}
		if !strings.Contains(strings.ToLower(rel), cidLower) {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			v2Paths = append(v2Paths, rel)
		} else {
			v1Paths = append(v1Paths, rel)
		}
	}
	for _, rel := range append(v2Paths, v1Paths...) {
		fullPath := filepath.Clean(filepath.Join(cleanRoot, filepath.FromSlash(rel)))
		if fullPath == cleanRoot || !strings.HasPrefix(fullPath, cleanRoot+string(filepath.Separator)) {
			continue
		}
		if ino, err := statFn(fullPath); err == nil && ino != 0 {
			return ino, nil
		}
	}
	return 0, os.ErrNotExist
}

func findCgroupDirByContainerID(cgroupRoot, containerID string, statFn func(string) (uint64, error)) (uint64, error) {
	cidLower := strings.ToLower(containerID)
	if cidLower == "" || statFn == nil {
		return 0, os.ErrNotExist
	}
	cleanRoot := filepath.Clean(cgroupRoot)
	var matched uint64
	stopWalk := fs.SkipAll
	_ = filepath.WalkDir(cleanRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fs.SkipDir
		}
		rel, rErr := filepath.Rel(cleanRoot, path)
		if rErr != nil || rel == "." {
			return nil
		}
		if strings.Count(rel, string(filepath.Separator)) > 6 {
			return fs.SkipDir
		}
		if strings.Contains(strings.ToLower(d.Name()), cidLower) {
			if ino, sErr := statFn(path); sErr == nil && ino != 0 {
				matched = ino
				return stopWalk
			}
		}
		return nil
	})
	if matched != 0 {
		return matched, nil
	}
	return 0, os.ErrNotExist
}
