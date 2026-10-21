//go:build ignore
// +build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#define MIN_EGRESS_THRESHOLD (64 * 1024)
#define SENSITIVE_THRESHOLD  1
#define PATH_MAX_LEN 128

#define EVENT_TYPE_EXFIL 1
#define EVENT_TYPE_EXEC  2

struct event {
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 daddr;
    __u16 dport;
    __u8  comm[16];
    __u8  filename[PATH_MAX_LEN];
    __u64 bytes_read;
    __u64 bytes_sent;
} __attribute__((packed));

struct io_stats {
    __u64 bytes_read;
    __u64 bytes_sent;
    __u32 daddr;
    __u16 dport;
    __u8  filename[PATH_MAX_LEN];
    __u8  alerted;
    __u8  is_sensitive;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct io_stats);
} proc_track SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Verifier-safe helper to detect sensitive target paths
static __always_inline __u8 check_path_sensitivity(const char *path) {
    #pragma unroll
    for (int i = 0; i < 96; i++) {
        if (path[i] == '\0') break;

        // Check for "/etc/shadow"
        if (path[i] == '/' && path[i+1] == 'e' && path[i+2] == 't' && path[i+3] == 'c' &&
            path[i+4] == '/' && path[i+5] == 's' && path[i+6] == 'h' && path[i+7] == 'a' &&
            path[i+8] == 'd' && path[i+9] == 'o' && path[i+10] == 'w') {
            return 1;
        }

        // Check for SSH private keys: "id_" (e.g., id_rsa, id_ed25519)
        if (path[i] == 'i' && path[i+1] == 'd' && path[i+2] == '_') {
            return 1;
        }

        // Check for ".env"
        if (path[i] == '.' && path[i+1] == 'e' && path[i+2] == 'n' && path[i+3] == 'v') {
            return 1;
        }

        // Check for ".aws/"
        if (path[i] == '.' && path[i+1] == 'a' && path[i+2] == 'w' && path[i+3] == 's' && path[i+4] == '/') {
            return 1;
        }
    }
    return 0;
}

// 1. Capture file paths opened via openat()
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    const char *filename_ptr = (const char *)ctx->args[1];
    if (!filename_ptr)
        return 0;

    char current_path[PATH_MAX_LEN] = {};
    if (bpf_probe_read_user_str(current_path, sizeof(current_path), filename_ptr) <= 0)
        return 0;

    __u8 sensitive = check_path_sensitivity(current_path);

    struct io_stats *stats = bpf_map_lookup_elem(&proc_track, &tgid);
    if (!stats) {
        struct io_stats init = {
            .is_sensitive = sensitive,
        };
        __builtin_memcpy(init.filename, current_path, sizeof(init.filename));
        bpf_map_update_elem(&proc_track, &tgid, &init, BPF_ANY);
    } else {
        __builtin_memcpy(stats->filename, current_path, sizeof(stats->filename));
        // Once a process touches a sensitive file, keep it marked sensitive
        if (sensitive) {
            stats->is_sensitive = 1;
        }
    }
    return 0;
}

// 2. Track process executions and extract command line arguments (argv)
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct trace_event_raw_sys_enter *ctx) {
    const char *const *argv = (const char *const *)ctx->args[1];
    if (!argv)
        return 0;

    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    const char *arg0_ptr = NULL;
    char arg0[32] = {};
    if (bpf_probe_read_user(&arg0_ptr, sizeof(arg0_ptr), (void *)argv) == 0 && arg0_ptr) {
        bpf_probe_read_user_str(arg0, sizeof(arg0), arg0_ptr);
    }

    int match = 0;
    if (__builtin_memcmp(comm, "scp", 3) == 0) match = 1;
    else if (__builtin_memcmp(comm, "rsync", 5) == 0) match = 1;
    else if (__builtin_memcmp(comm, "ssh", 3) == 0) match = 1;

    if (!match) {
        #pragma unroll
        for (int i = 0; i < 26; i++) {
            if (arg0[i] == '/' && arg0[i+1] == 's' && arg0[i+2] == 'c' && arg0[i+3] == 'p' && arg0[i+4] == '\0') {
                match = 1;
                __builtin_memcpy(comm, "scp", 4);
                break;
            }
            if (arg0[i] == '/' && arg0[i+1] == 'r' && arg0[i+2] == 's' && arg0[i+3] == 'y' && arg0[i+4] == 'n' && arg0[i+5] == 'c' && arg0[i+6] == '\0') {
                match = 1;
                __builtin_memcpy(comm, "rsync", 6);
                break;
            }
            if (arg0[i] == '/' && arg0[i+1] == 's' && arg0[i+2] == 's' && arg0[i+3] == 'h' && arg0[i+4] == '\0') {
                match = 1;
                __builtin_memcpy(comm, "ssh", 4);
                break;
            }
            if (arg0[i] == '\0') break;
        }
    }

    if (!match)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 ppid = 0;
    if (task) {
        struct task_struct *parent = NULL;
        BPF_CORE_READ_INTO(&parent, task, real_parent);
        if (parent) {
            BPF_CORE_READ_INTO(&ppid, parent, tgid);
        }
    }

    e->event_type = EVENT_TYPE_EXEC;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = ppid;
    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    const char *arg1_ptr = NULL;
    if (bpf_probe_read_user(&arg1_ptr, sizeof(arg1_ptr), (void *)(argv + 1)) == 0 && arg1_ptr) {
        bpf_probe_read_user_str(e->filename, sizeof(e->filename), arg1_ptr);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// 3. Track external connections (filtering out loopback and 0.0.0.0)
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    struct sockaddr_in *user_addr = (struct sockaddr_in *)ctx->args[1];
    if (!user_addr)
        return 0;

    struct sockaddr_in kaddr = {};
    if (bpf_probe_read_user(&kaddr, sizeof(kaddr), user_addr) != 0)
        return 0;

    if (kaddr.sin_family != AF_INET)
        return 0;

    // Filter 0.0.0.0 and port 0
    if (kaddr.sin_addr.s_addr == 0 || kaddr.sin_port == 0)
        return 0;

    // Filter loopback (127.0.0.0/8)
    if ((kaddr.sin_addr.s_addr & 0xFF) == 127)
        return 0;

    struct io_stats *stats = bpf_map_lookup_elem(&proc_track, &tgid);
    if (!stats) {
        struct io_stats init = {
            .daddr = kaddr.sin_addr.s_addr,
            .dport = kaddr.sin_port,
        };
        bpf_map_update_elem(&proc_track, &tgid, &init, BPF_ANY);
    } else {
        stats->daddr = kaddr.sin_addr.s_addr;
        stats->dport = kaddr.sin_port;
    }
    return 0;
}

// 4. Track file reads
SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx) {
    long ret = ctx->ret;
    if (ret <= 0)
        return 0;

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct io_stats *stats = bpf_map_lookup_elem(&proc_track, &tgid);
    if (stats) {
        stats->bytes_read += ret;
    }
    return 0;
}

// Helper to evaluate dual-counter threshold (sensitive vs generic)
static __always_inline void check_and_emit(__u32 tgid, struct io_stats *stats, long sent_len) {
    stats->bytes_sent += sent_len;

    if (stats->daddr == 0 || stats->dport == 0)
        return;

    __u64 required_thresh = stats->is_sensitive ? SENSITIVE_THRESHOLD : MIN_EGRESS_THRESHOLD;

    if (!stats->alerted && stats->bytes_sent >= required_thresh && stats->bytes_read >= required_thresh) {
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            return;

        e->event_type = EVENT_TYPE_EXFIL;
        e->pid = tgid;
        e->ppid = 0;
        e->daddr = stats->daddr;
        e->dport = stats->dport;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        __builtin_memcpy(e->filename, stats->filename, sizeof(e->filename));
        e->bytes_read = stats->bytes_read;
        e->bytes_sent = stats->bytes_sent;

        stats->alerted = 1;
        bpf_ringbuf_submit(e, 0);
    }
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto_enter(struct trace_event_raw_sys_enter *ctx) {
    long len = (long)ctx->args[2];
    if (len <= 0) return 0;

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct io_stats *stats = bpf_map_lookup_elem(&proc_track, &tgid);
    if (!stats) return 0;

    check_and_emit(tgid, stats, len);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx) {
    long len = (long)ctx->args[2];
    if (len <= 0) return 0;

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct io_stats *stats = bpf_map_lookup_elem(&proc_track, &tgid);
    if (!stats) return 0;

    check_and_emit(tgid, stats, len);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
