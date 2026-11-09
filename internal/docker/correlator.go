package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alexno10/seccomp-profiler/internal/ebpf"
	"github.com/alexno10/seccomp-profiler/internal/selector"
)

var hex64Regex = regexp.MustCompile(`[0-9a-f]{64}`)

type DockerEvent struct {
	Action   string
	ID       string
	Image    string
	Name     string
	Labels   map[string]string
	TimeNano int64
}

type InodeResolver func(containerID string) (uint64, error)

type containerMeta struct {
	id        string
	name      string
	image     string
	labels    map[string]string
	startNano int64
	endNano   int64
}

type Correlator struct {
	mu           sync.Mutex
	resolver     InodeResolver
	containers   map[string]*containerMeta
	cgroupToCID  map[uint64]string
	cgroupBins   map[uint64][]string
}

func NewCorrelator(resolver InodeResolver) *Correlator {
	if resolver == nil {
		resolver = DefaultResolveContainerCgroupInode
	}
	return &Correlator{
		resolver:    resolver,
		containers:  make(map[string]*containerMeta),
		cgroupToCID: make(map[uint64]string),
		cgroupBins:  make(map[uint64][]string),
	}
}

func ExtractContainerID(cgroupPath string) (string, bool) {
	m := hex64Regex.FindString(strings.ToLower(cgroupPath))
	if m == "" {
		return "", false
	}
	return m, true
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
	if ev.Image != "" {
		meta.image = ev.Image
	}
	if ev.Name != "" {
		meta.name = ev.Name
	}
	for k, v := range ev.Labels {
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
		if ev.TimeNano > 0 {
			meta.startNano = ev.TimeNano
		}
		resolveID = ev.ID
	case "die", "stop", "destroy":
		if ev.TimeNano > 0 && meta.endNano == 0 {
			meta.endNano = ev.TimeNano
		}
	}
	c.mu.Unlock()

	if resolveID != "" && c.resolver != nil {
		if ino, err := c.resolver(resolveID); err == nil && ino != 0 {
			c.mu.Lock()
			c.cgroupToCID[ino] = resolveID
			c.mu.Unlock()
		}
	}
}

func (c *Correlator) BindCgroup(cgroupID uint64, containerID string) {
	if cgroupID == 0 || containerID == "" {
		return
	}
	c.mu.Lock()
	c.cgroupToCID[cgroupID] = containerID
	c.mu.Unlock()
}

func (c *Correlator) RecordKernelEvent(ev ebpf.KernelEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ev.CgroupPath != "" {
		if cid, ok := ExtractContainerID(ev.CgroupPath); ok {
			c.cgroupToCID[ev.CgroupID] = cid
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

	for cgID, st := range stats {
		cid := c.cgroupToCID[cgID]
		if cid == "" {
			continue
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
				for k, v := range meta.labels {
					rec.Labels[k] = v
				}
				if meta.startNano > 0 && meta.endNano >= meta.startNano {
					rec.DurationMs = (meta.endNano - meta.startNano) / 1_000_000
				}
			}
			if rec.Image == "" {
				rec.Image = cid[:12]
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

	var out []selector.ContainerRecord
	for _, r := range byCID {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
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
		if k == "image" || k == "name" {
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

func StreamDockerEvents(ctx context.Context, onEvent func(DockerEvent)) error {
	since := fmt.Sprintf("%d", time.Now().Add(-5*time.Second).Unix())
	cmd := exec.CommandContext(ctx, "docker", "events", "--since", since, "--filter", "type=container", "--format", "{{json .}}")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		ev, err := ParseDockerEventJSON(sc.Bytes())
		if err == nil && ev.ID != "" {
			onEvent(ev)
		}
	}
	_ = cmd.Wait()
	return nil
}

func ScanRunningContainers(ctx context.Context) ([]DockerEvent, map[string]uint64, error) {
	out, err := exec.CommandContext(ctx, "docker", "ps", "-q", "--no-trunc").Output()
	if err != nil {
		return nil, nil, err
	}
	var events []DockerEvent
	inodes := make(map[string]uint64)
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		cid := strings.TrimSpace(line)
		if cid == "" {
			continue
		}
		inspOut, err := exec.CommandContext(ctx, "docker", "inspect", cid).Output()
		if err != nil {
			continue
		}
		var inspected []struct {
			Id     string `json:"Id"`
			Name   string `json:"Name"`
			Config struct {
				Image  string            `json:"Image"`
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
		}
		if err := json.Unmarshal(inspOut, &inspected); err != nil || len(inspected) == 0 {
			continue
		}
		item := inspected[0]
		events = append(events, DockerEvent{
			Action: "start",
			ID:     item.Id,
			Image:  item.Config.Image,
			Name:   strings.TrimPrefix(item.Name, "/"),
			Labels: item.Config.Labels,
		})
		if ino, err := DefaultResolveContainerCgroupInode(item.Id); err == nil && ino != 0 {
			inodes[item.Id] = ino
		}
	}
	return events, inodes, nil
}

func DefaultResolveContainerCgroupInode(containerID string) (uint64, error) {
	candidates := []string{
		filepath.Join("/sys/fs/cgroup/system.slice", fmt.Sprintf("docker-%s.scope", containerID)),
		filepath.Join("/sys/fs/cgroup/docker", containerID),
	}
	for _, p := range candidates {
		if ino, err := statInode(p); err == nil && ino != 0 {
			return ino, nil
		}
	}
	out, err := exec.Command("docker", "inspect", "--format", "{{.State.Pid}}", containerID).Output()
	if err != nil {
		return 0, err
	}
	pid := strings.TrimSpace(string(bytes.TrimSpace(out)))
	if pid == "" || pid == "0" {
		return 0, os.ErrNotExist
	}
	cgBytes, err := os.ReadFile(filepath.Join("/proc", pid, "cgroup"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(cgBytes), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 3)
		if len(parts) == 3 && parts[2] != "" {
			fullPath := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(parts[2], "/"))
			if ino, err := statInode(fullPath); err == nil && ino != 0 {
				return ino, nil
			}
		}
	}
	return 0, os.ErrNotExist
}

func statInode(path string) (uint64, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	sys := fi.Sys()
	if sys == nil {
		return 0, fmt.Errorf("no underlying stat info for %s", path)
	}
	v := reflect.ValueOf(sys)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return 0, fmt.Errorf("unexpected stat type for %s", path)
	}
	f := v.FieldByName("Ino")
	if !f.IsValid() {
		return 0, fmt.Errorf("no Ino field on stat for %s", path)
	}
	return f.Uint(), nil
}
