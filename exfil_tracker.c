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
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct io_stats);
} proc_track SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct scratch_buf {
    struct io_stats stats;
    char path1[PATH_MAX_LEN];
    char path2[PATH_MAX_LEN];
    char arg0[32];
    char matched_tool[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scratch_buf);
} scratch_map SEC(".maps");

static __always_inline struct scratch_buf *get_scratch(void) {
    __u32 zero = 0;
    return bpf_map_lookup_elem(&scratch_map, &zero);
}

// Verifier-safe helper to detect sensitive target paths
static __always_inline __u8 check_path_sensitivity(const char *path) {
    #pragma unroll
    for (int i = 0; i < 48; i++) {
        if (path[i] == '\0') break;

        // Check for "shadow"
        if (path[i] == 's' && path[i+1] == 'h' && path[i+2] == 'a' &&
            path[i+3] == 'd' && path[i+4] == 'o' && path[i+5] == 'w') {
            return 1;
        }

        // Check for "passwd"
        if (path[i] == 'p' && path[i+1] == 'a' && path[i+2] == 's' &&
            path[i+3] == 's' && path[i+4] == 'w' && path[i+5] == 'd') {
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

        // Check for ".aws"
        if (path[i] == '.' && path[i+1] == 'a' && path[i+2] == 'w' && path[i+3] == 's') {
            return 1;
        }

        // Check for ".ssh"
        if (path[i] == '.' && path[i+1] == 's' && path[i+2] == 's' && path[i+3] == 'h') {
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

    struct scratch_buf *scr = get_scratch();
    if (!scr)
        return 0;

    __builtin_memset(scr->path1, 0, sizeof(scr->path1));
    if (bpf_probe_read_user_str(scr->path1, sizeof(scr->path1), filename_ptr) <= 0)
        return 0;

    __u8 sensitive = check_path_sensitivity(scr->path1);

    struct io_stats *stats = bpf_map_lookup_elem(&proc_track, &tgid);
    if (!stats) {
        __builtin_memset(&scr->stats, 0, sizeof(scr->stats));
        scr->stats.is_sensitive = sensitive;
        __builtin_memcpy(scr->stats.filename, scr->path1, sizeof(scr->stats.filename));
        bpf_map_update_elem(&proc_track, &tgid, &scr->stats, BPF_ANY);
    } else {
        // Protect sensitive filename: never overwrite sensitive filename with non-sensitive ones
        if (sensitive) {
            __builtin_memcpy(stats->filename, scr->path1, sizeof(stats->filename));
            stats->is_sensitive = 1;
        } else if (!stats->is_sensitive) {
            __builtin_memcpy(stats->filename, scr->path1, sizeof(stats->filename));
        }
    }
    return 0;
}

// Helper to check tool name against known suspicious tools
static __always_inline int match_suspicious_tool(const char *arg0, char *matched_name) {
    #pragma unroll
    for (int i = 0; i < 28; i++) {
        const char *p = (i == 0) ? arg0 : (arg0[i-1] == '/' ? &arg0[i] : NULL);
        if (!p) {
            if (arg0[i] == '\0') break;
            continue;
        }

        if (p[0] == 's' && p[1] == 'c' && p[2] == 'p' && (p[3] == '\0' || p[3] == ' ')) {
            __builtin_memcpy(matched_name, "scp", 4);
            return 1;
        }
        if (p[0] == 'c' && p[1] == 'u' && p[2] == 'r' && p[3] == 'l' && (p[4] == '\0' || p[4] == ' ')) {
            __builtin_memcpy(matched_name, "curl", 5);
            return 1;
        }
        if (p[0] == 'w' && p[1] == 'g' && p[2] == 'e' && p[3] == 't' && (p[4] == '\0' || p[4] == ' ')) {
            __builtin_memcpy(matched_name, "wget", 5);
            return 1;
        }
        if (p[0] == 'r' && p[1] == 's' && p[2] == 'y' && p[3] == 'n' && p[4] == 'c' && (p[5] == '\0' || p[5] == ' ')) {
            __builtin_memcpy(matched_name, "rsync", 6);
            return 1;
        }
        if (p[0] == 's' && p[1] == 's' && p[2] == 'h' && (p[3] == '\0' || p[3] == ' ')) {
            __builtin_memcpy(matched_name, "ssh", 4);
            return 1;
        }
        if (p[0] == 's' && p[1] == 'f' && p[2] == 't' && p[3] == 'p' && (p[4] == '\0' || p[4] == ' ')) {
            __builtin_memcpy(matched_name, "sftp", 5);
            return 1;
        }
        if (p[0] == 'n' && p[1] == 'c' && (p[2] == '\0' || p[2] == ' ')) {
            __builtin_memcpy(matched_name, "nc", 3);
            return 1;
        }
        if (p[0] == 'n' && p[1] == 'c' && p[2] == 'a' && p[3] == 't' && (p[4] == '\0' || p[4] == ' ')) {
            __builtin_memcpy(matched_name, "ncat", 5);
            return 1;
        }
        if (p[0] == 's' && p[1] == 'o' && p[2] == 'c' && p[3] == 'a' && p[4] == 't' && (p[5] == '\0' || p[5] == ' ')) {
            __builtin_memcpy(matched_name, "socat", 6);
            return 1;
        }
        if (arg0[i] == '\0') break;
    }
    return 0;
}

// 2. Track process executions and extract command line arguments (argv)
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct trace_event_raw_sys_enter *ctx) {
    const char *const *argv = (const char *const *)ctx->args[1];
    if (!argv)
        return 0;

    struct scratch_buf *scr = get_scratch();
    if (!scr)
        return 0;

    __builtin_memset(scr->arg0, 0, sizeof(scr->arg0));
    __builtin_memset(scr->matched_tool, 0, sizeof(scr->matched_tool));

    const char *arg0_ptr = NULL;
    if (bpf_probe_read_user(&arg0_ptr, sizeof(arg0_ptr), (void *)argv) != 0 || !arg0_ptr) {
        return 0;
    }
    bpf_probe_read_user_str(scr->arg0, sizeof(scr->arg0), arg0_ptr);

    if (!match_suspicious_tool(scr->arg0, scr->matched_tool)) {
        const char *bin_path = (const char *)ctx->args[0];
        if (bin_path) {
            __builtin_memset(scr->arg0, 0, sizeof(scr->arg0));
            if (bpf_probe_read_user_str(scr->arg0, sizeof(scr->arg0), bin_path) <= 0)
                return 0;
            if (!match_suspicious_tool(scr->arg0, scr->matched_tool))
                return 0;
        } else {
            return 0;
        }
    }

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    __u32 ppid = 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = NULL;
        parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            ppid = BPF_CORE_READ(parent, tgid);
        }
    }

    // Process hierarchy correlation: check if parent is tracked (e.g. scp spawning ssh)
    if (ppid) {
        struct io_stats *pstats = bpf_map_lookup_elem(&proc_track, &ppid);
        if (pstats && (pstats->is_sensitive || pstats->filename[0] != '\0')) {
            // Child transport process inherits target filename and sensitivity from parent
            __builtin_memcpy(&scr->stats, pstats, sizeof(scr->stats));
            scr->stats.alerted = 0;
            scr->stats.bytes_sent = 0;
            bpf_map_update_elem(&proc_track, &tgid, &scr->stats, BPF_ANY);

            // Suppress redundant internal helper alert (e.g. ssh spawned by scp)
            if (__builtin_memcmp(scr->matched_tool, "ssh", 3) == 0 || __builtin_memcmp(scr->matched_tool, "sftp", 4) == 0) {
                return 0;
            }
        }
    }

    // Scan argv for target file (skip leading flags, prioritize sensitive files)
    // Use scr->path1 as target_buf, scr->path2 as temp_arg
    __builtin_memset(scr->path1, 0, sizeof(scr->path1));
    __u8 target_is_sensitive = 0;

    #pragma unroll
    for (int i = 1; i <= 5; i++) {
        const char *arg_ptr = NULL;
        if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), (void *)(argv + i)) != 0 || !arg_ptr)
            break;

        __builtin_memset(scr->path2, 0, sizeof(scr->path2));
        if (bpf_probe_read_user_str(scr->path2, sizeof(scr->path2), arg_ptr) <= 0)
            break;

        if (scr->path2[0] == '-')
            continue;

        if (check_path_sensitivity(scr->path2)) {
            __builtin_memcpy(scr->path1, scr->path2, sizeof(scr->path1));
            target_is_sensitive = 1;
            break;
        }

        if (scr->path1[0] == '\0') {
            int is_remote = 0;
            #pragma unroll
            for (int j = 0; j < 24; j++) {
                if (scr->path2[j] == '\0') break;
                if (scr->path2[j] == '@' || (scr->path2[j] == ':' && scr->path2[j+1] == '/')) {
                    is_remote = 1;
                    break;
                }
            }
            if (!is_remote) {
                __builtin_memcpy(scr->path1, scr->path2, sizeof(scr->path1));
            }
        }
    }

    // Register or update tracking entry for this PID
    struct io_stats *stats = bpf_map_lookup_elem(&proc_track, &tgid);
    if (!stats) {
        __builtin_memset(&scr->stats, 0, sizeof(scr->stats));
        scr->stats.is_sensitive = target_is_sensitive;
        __builtin_memcpy(scr->stats.filename, scr->path1, sizeof(scr->stats.filename));
        bpf_map_update_elem(&proc_track, &tgid, &scr->stats, BPF_ANY);
    } else {
        if (target_is_sensitive || !stats->is_sensitive) {
            __builtin_memcpy(stats->filename, scr->path1, sizeof(stats->filename));
        }
        if (target_is_sensitive) {
            stats->is_sensitive = 1;
        }
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->event_type = EVENT_TYPE_EXEC;
    e->pid = tgid;
    e->ppid = ppid;
    __builtin_memcpy(e->comm, scr->matched_tool, sizeof(e->comm));
    __builtin_memcpy(e->filename, scr->path1, sizeof(e->filename));

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
        struct scratch_buf *scr = get_scratch();
        if (!scr)
            return 0;

        // Fallback parent correlation if child connected without execve tracking
        __u32 ppid = 0;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        if (task) {
            struct task_struct *parent = BPF_CORE_READ(task, real_parent);
            if (parent) {
                ppid = BPF_CORE_READ(parent, tgid);
            }
        }
        struct io_stats *pstats = ppid ? bpf_map_lookup_elem(&proc_track, &ppid) : NULL;

        __builtin_memset(&scr->stats, 0, sizeof(scr->stats));
        scr->stats.daddr = kaddr.sin_addr.s_addr;
        scr->stats.dport = kaddr.sin_port;
        if (pstats) {
            __builtin_memcpy(scr->stats.filename, pstats->filename, sizeof(scr->stats.filename));
            scr->stats.is_sensitive = pstats->is_sensitive;
            scr->stats.bytes_read = pstats->bytes_read;
        }
        bpf_map_update_elem(&proc_track, &tgid, &scr->stats, BPF_ANY);
    } else {
        stats->daddr = kaddr.sin_addr.s_addr;
        stats->dport = kaddr.sin_port;
    }
    return 0;
}

// 4. Track file reads
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx) {
    long count = (long)ctx->args[2];
    if (count <= 0)
        return 0;

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct io_stats *stats = bpf_map_lookup_elem(&proc_track, &tgid);
    if (stats) {
        stats->bytes_read += count;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pread64")
int trace_pread64_enter(struct trace_event_raw_sys_enter *ctx) {
    long count = (long)ctx->args[2];
    if (count <= 0)
        return 0;

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct io_stats *stats = bpf_map_lookup_elem(&proc_track, &tgid);
    if (stats) {
        stats->bytes_read += count;
    }
    return 0;
}

// Helper to evaluate dual-counter threshold (sensitive vs generic)
static __always_inline void check_and_emit(__u32 tgid, struct io_stats *stats, long sent_len) {
    stats->bytes_sent += sent_len;

    if (stats->daddr == 0 || stats->dport == 0)
        return;

    __u64 required_thresh = stats->is_sensitive ? SENSITIVE_THRESHOLD : MIN_EGRESS_THRESHOLD;
    __u8 read_ready = stats->is_sensitive ? (stats->bytes_read > 0 || stats->filename[0] != '\0') : (stats->bytes_read >= required_thresh);

    if (!stats->alerted && stats->bytes_sent >= required_thresh && read_ready) {
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
        e->bytes_read = stats->bytes_read > 0 ? stats->bytes_read : sent_len;
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

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct io_stats *stats = bpf_map_lookup_elem(&proc_track, &tgid);
    if (!stats) return 0;

    check_and_emit(tgid, stats, 512);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_writev_enter(struct trace_event_raw_sys_enter *ctx) {
    long len = (long)ctx->args[2];
    if (len <= 0) len = 512;

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct io_stats *stats = bpf_map_lookup_elem(&proc_track, &tgid);
    if (!stats) return 0;

    check_and_emit(tgid, stats, len);
    return 0;
}

// 5. Clean up process stats on exit to prevent BPF hash map starvation
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx) {
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&proc_track, &tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
