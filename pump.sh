#!/bin/bash

#!/bin/bash
set -e

# 1. Generate kernel headers
echo "[+] Generating vmlinux.h..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. Ensure bpf2go is present and discoverable in PATH
echo "[+] Installing bpf2go..."
go install github.com/cilium/ebpf/cmd/bpf2go@latest
export PATH="$PATH:$(go env GOPATH)/bin"

# 3. Sync dependencies
echo "[+] Syncing Go dependencies..."
go get github.com/cilium/ebpf@latest
go mod tidy

# 4. Generate C-to-Go bindings and compile binary
echo "[+] Running bpf2go generation..."
go generate

echo "[+] Building binary..."
go build -o exfil-monitor .

echo "[✓] Build complete: ./exfil-monitor"
