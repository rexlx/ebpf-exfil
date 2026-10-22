package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -Wno-missing-declarations" bpf exfil_tracker.c

const (
	EventTypeExfil = 1
	EventTypeExec  = 2
)

var daemonWhitelist = map[string]bool{
	"squid":            true,
	"squid-1":          true,
	"grafana":          true,
	"grafana-server":   true,
	"systemd-resolved": true,
	"systemd-timesyn":  true,
	"chronyd":          true,
	"threatcontrol":    true,
	"threatco":         true,
	"dockerd":          true,
	"containerd":       true,
	"prometheus":       true,
	"node_exporter":    true,
	"php-fpm":          true,
	"php-fpm8.2":       true,
	"php-fpm8.3":       true,
}

var ipWhitelist = map[string]bool{
	"104.236.102.152": true, // Automation / droplet destination
}

var dockerNet *net.IPNet

func init() {
	var err error
	_, dockerNet, err = net.ParseCIDR("172.19.0.0/16")
	if err != nil {
		log.Fatalf("failed to parse dockerNet CIDR: %v", err)
	}
}

type Event struct {
	EventType uint32
	PID       uint32
	PPID      uint32
	DAddr     [4]byte
	DPort     uint16
	Comm      [16]byte
	Filename  [128]byte
	BytesRead uint64
	BytesSent uint64
}

type Logger interface {
	Notice(msg string) error
	Warning(msg string) error
	Info(msg string) error
	Close() error
}

type DualLogger struct {
	syslog Logger
}

func (d *DualLogger) Notice(msg string) error {
	log.Printf("[NOTICE] %s", msg)
	if d.syslog != nil {
		if err := d.syslog.Notice(msg); err != nil {
			log.Printf("[SYSLOG-ERROR] failed to send notice: %v", err)
			return err
		}
	}
	return nil
}

func (d *DualLogger) Warning(msg string) error {
	log.Printf("[ALERT]  %s", msg)
	if d.syslog != nil {
		if err := d.syslog.Warning(msg); err != nil {
			log.Printf("[SYSLOG-ERROR] failed to send warning: %v", err)
			return err
		}
	}
	return nil
}

func (d *DualLogger) Info(msg string) error {
	log.Printf("[INFO]   %s", msg)
	if d.syslog != nil {
		if err := d.syslog.Info(msg); err != nil {
			log.Printf("[SYSLOG-ERROR] failed to send info: %v", err)
			return err
		}
	}
	return nil
}

func (d *DualLogger) Close() error {
	if d.syslog != nil {
		return d.syslog.Close()
	}
	return nil
}

func setupLogger(mode, proto, addr string) (Logger, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	} else {
		if idx := strings.Index(hostname, "."); idx != -1 {
			hostname = hostname[:idx]
		}
	}

	tag := fmt.Sprintf("exfil-monitor-%s", hostname)

	var backend Logger
	switch mode {
	case "local":
		sys, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_DAEMON, tag)
		if err != nil {
			return nil, err
		}
		backend = sys
	case "remote":
		if addr == "" {
			return nil, fmt.Errorf("syslog-addr required for remote syslog")
		}
		sys, err := syslog.Dial(proto, addr, syslog.LOG_NOTICE|syslog.LOG_DAEMON, tag)
		if err != nil {
			return nil, err
		}
		backend = sys
	case "stdout":
		backend = nil
	default:
		return nil, fmt.Errorf("unknown syslog mode: %s (choose stdout, local, remote)", mode)
	}

	return &DualLogger{syslog: backend}, nil
}

func nullTerminatedString(b []byte) string {
	if idx := bytes.IndexByte(b, 0); idx != -1 {
		return string(b[:idx])
	}
	return string(b)
}

func startMapSweeper(procMap *ebpf.Map, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		valBuf := make([]byte, procMap.ValueSize())
		for range ticker.C {
			var (
				key      uint32
				toDelete []uint32
			)
			iter := procMap.Iterate()
			for iter.Next(&key, valBuf) {
				procPath := fmt.Sprintf("/proc/%d", key)
				if _, err := os.Stat(procPath); os.IsNotExist(err) {
					toDelete = append(toDelete, key)
				}
			}
			if err := iter.Err(); err != nil {
				log.Printf("[SWEEPER] error iterating proc_track: %v", err)
			}
			for _, pid := range toDelete {
				_ = procMap.Delete(pid)
			}
			if len(toDelete) > 0 {
				log.Printf("[SWEEPER] Purged %d dead process entries from proc_track", len(toDelete))
			}
		}
	}()
}

func computeFileHash(pid uint32, rawPath string) (string, string) {
	if rawPath == "" || strings.HasPrefix(rawPath, "-") {
		return "N/A", rawPath
	}

	targetPath := rawPath
	if !filepath.IsAbs(rawPath) {
		cwdPath := fmt.Sprintf("/proc/%d/cwd", pid)
		realCwd, err := os.Readlink(cwdPath)
		if err == nil {
			targetPath = filepath.Join(realCwd, rawPath)
		}
	}

	f, err := os.Open(targetPath)
	if err != nil {
		procRootPath := fmt.Sprintf("/proc/%d/root/%s", pid, strings.TrimPrefix(targetPath, "/"))
		f, err = os.Open(procRootPath)
		if err != nil {
			return "File closed / unreadable", targetPath
		}
	}
	defer f.Close()

	// Never block on pipes, fifos, or special character devices
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return "N/A (not regular file)", targetPath
	}

	hasher := sha256.New()
	if _, err := io.CopyN(hasher, f, 32*1024*1024); err != nil && err != io.EOF {
		return "Error computing hash", targetPath
	}

	return hex.EncodeToString(hasher.Sum(nil)), targetPath
}

func isIgnoredDestination(ip net.IP, port uint16) bool {
	if ip.IsUnspecified() || ip.Equal(net.IPv4zero) || ip.IsLoopback() || port == 0 {
		return true
	}

	if dockerNet != nil && dockerNet.Contains(ip) {
		return true
	}

	return false
}

func main() {
	mode := flag.String("syslog", "stdout", "Logging destination: 'stdout', 'local', or 'remote'")
	proto := flag.String("syslog-proto", "udp", "Protocol for remote syslog: 'udp' or 'tcp'")
	addr := flag.String("syslog-addr", "", "Host:port destination for remote syslog (e.g. 192.168.86.120:514)")
	flag.Parse()

	sysLogger, err := setupLogger(*mode, *proto, *addr)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer sysLogger.Close()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to unlock memlock: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Periodically sweep dead process entries from proc_track without restarting the service
	startMapSweeper(objs.ProcTrack, 5*time.Minute)

	kpOpen, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenatEnter, nil)
	if err != nil {
		log.Fatalf("attaching openat tracepoint: %v", err)
	}
	defer kpOpen.Close()

	kpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecveEnter, nil)
	if err != nil {
		log.Fatalf("attaching execve tracepoint: %v", err)
	}
	defer kpExec.Close()

	kpConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnectEnter, nil)
	if err != nil {
		log.Fatalf("attaching connect tracepoint: %v", err)
	}
	defer kpConnect.Close()

	kpRead, err := link.Tracepoint("syscalls", "sys_enter_read", objs.TraceReadEnter, nil)
	if err != nil {
		log.Fatalf("attaching read tracepoint: %v", err)
	}
	defer kpRead.Close()

	if kpPread, err := link.Tracepoint("syscalls", "sys_enter_pread64", objs.TracePread64Enter, nil); err == nil {
		defer kpPread.Close()
	}

	kpSend, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.TraceSendtoEnter, nil)
	if err != nil {
		log.Fatalf("attaching sendto tracepoint: %v", err)
	}
	defer kpSend.Close()

	kpWrite, err := link.Tracepoint("syscalls", "sys_enter_write", objs.TraceWriteEnter, nil)
	if err != nil {
		log.Fatalf("attaching write tracepoint: %v", err)
	}
	defer kpWrite.Close()

	if kpSendmsg, err := link.Tracepoint("syscalls", "sys_enter_sendmsg", objs.TraceSendmsgEnter, nil); err == nil {
		defer kpSendmsg.Close()
	}

	if kpWritev, err := link.Tracepoint("syscalls", "sys_enter_writev", objs.TraceWritevEnter, nil); err == nil {
		defer kpWritev.Close()
	}

	kpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceSchedProcessExit, nil)
	if err != nil {
		log.Fatalf("attaching sched_process_exit tracepoint: %v", err)
	}
	defer kpExit.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuffer reader: %v", err)
	}
	defer rd.Close()

	sysLogger.Info(fmt.Sprintf("eBPF Exfil Monitor started. Target: %s", *mode))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				log.Printf("[ERROR] ringbuf reader returned: %v", err)
				return
			}

			var event Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				continue
			}

			commName := nullTerminatedString(event.Comm[:])
			if daemonWhitelist[commName] {
				continue
			}

			switch event.EventType {
			case EventTypeExec:
				targetArg := nullTerminatedString(event.Filename[:])
				hash, resolvedPath := computeFileHash(event.PID, targetArg)

				alertMsg := fmt.Sprintf("Suspicious Tool Executed: binary=%s pid=%d ppid=%d target=%s sha256=%s",
					commName, event.PID, event.PPID, resolvedPath, hash)
				_ = sysLogger.Warning(alertMsg)

			case EventTypeExfil:
				ip := net.IP(event.DAddr[:])
				port := binary.BigEndian.Uint16([]byte{byte(event.DPort), byte(event.DPort >> 8)})

				if isIgnoredDestination(ip, port) {
					continue
				}

				if ipWhitelist[ip.String()] {
					continue
				}

				rawFilename := nullTerminatedString(event.Filename[:])
				hash, resolvedPath := computeFileHash(event.PID, rawFilename)

				readKB := event.BytesRead / 1024
				if readKB == 0 && event.BytesRead > 0 {
					readKB = 1
				}
				sentKB := event.BytesSent / 1024
				if sentKB == 0 && event.BytesSent > 0 {
					sentKB = 1
				}

				alertMsg := fmt.Sprintf("Exfiltration Detected: binary=%s pid=%d dest=%s:%d file=%s sha256=%s disk_read_kb=%d net_egress_kb=%d",
					commName, event.PID, ip.String(), port, resolvedPath, hash,
					readKB, sentKB)
				_ = sysLogger.Warning(alertMsg)
			}
		}
	}()

	<-sig
	sysLogger.Info("eBPF Exfil Monitor stopping...")
}
