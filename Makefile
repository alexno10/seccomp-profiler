.PHONY: all generate bpf bpf-amd64 bpf-arm64 build test clean

CLANG ?= clang
GO ?= go
VERSION ?= 1.1.1
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),aarch64)
BPF_ARCH_DEFINE ?= -D__TARGET_ARCH_arm64
else ifeq ($(UNAME_M),arm64)
BPF_ARCH_DEFINE ?= -D__TARGET_ARCH_arm64
else
BPF_ARCH_DEFINE ?= -D__TARGET_ARCH_x86
endif
BPF_CFLAGS ?= -O2 -g -ffile-prefix-map=$(CURDIR)=. -Wall -Werror -target bpf $(BPF_ARCH_DEFINE)
GO_LDFLAGS ?= -s -w -buildid= -X main.version=$(VERSION)

all: bpf build

generate:
	$(GO) generate ./internal/syscalls/...

bpf:
	$(CLANG) $(BPF_CFLAGS) -c bpf/profiler.bpf.c -o bpf/profiler.bpf.o
	cp bpf/profiler.bpf.o internal/ebpf/profiler.bpf.o

bpf-amd64:
	$(CLANG) -O2 -g -ffile-prefix-map=$(CURDIR)=. -Wall -Werror -target bpf -D__TARGET_ARCH_x86 -c bpf/profiler.bpf.c -o bpf/profiler.bpf.o
	cp bpf/profiler.bpf.o internal/ebpf/profiler.bpf.o

bpf-arm64:
	$(CLANG) -O2 -g -ffile-prefix-map=$(CURDIR)=. -Wall -Werror -target bpf -D__TARGET_ARCH_arm64 -c bpf/profiler.bpf.c -o bpf/profiler.bpf.o
	cp bpf/profiler.bpf.o internal/ebpf/profiler.bpf.o

build:
	CGO_ENABLED=0 $(GO) build -tags embed_bpf -trimpath -buildvcs=false -ldflags="$(GO_LDFLAGS)" -o bin/seccomp-profiler ./cmd/seccomp-profiler

test:
	$(GO) test ./... -v

clean:
	rm -rf bin/ dist/ bpf/*.o internal/ebpf/*.o
