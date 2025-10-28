// go:build ignore

#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>
#include <string.h>

struct event {
  __u32 pid;
  __u32 tid;
  __u64 goroutine;
  __u64 start_time;
  __u64 end_time;
  __u64 protoMajor;
  __u64 protoMinor;
  char host[256];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64); // goroutine ID as key
  __type(value, struct event);
  __uint(max_entries, 1024);
} traces SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

#if defined(bpf_target_arm64)
// https://go.dev/src/cmd/compile/abi-internal#arm64-architecture
#define goroutine_id(ctx) (__PT_REGS_CAST(ctx)->regs[28])
#elif defined(bpf_target_x86)
// https://go.dev/src/cmd/compile/abi-internal#amd64-architecture
// 動くかわからないので注意
#define goroutine_id(ctx) (__PT_REGS_CAST(ctx)->regs[14])
#endif

typedef struct go_str {
  char *str;
  unsigned int len;
} go_str_t;

SEC("uprobe/start_trace")
int uprobe_start_trace(struct pt_regs *ctx) {
  bpf_printk("uprobe_start_trace called\n");
  struct event event = {0};
  __u64 key = goroutine_id(ctx);

  event.tid = bpf_get_current_pid_tgid();
  event.pid = bpf_get_current_pid_tgid() >> 32;
  event.goroutine = key;
  event.start_time = bpf_ktime_get_ns();
  void *req = (void *)PT_REGS_PARM4(ctx);
  int protoMajor = 100;
  int protoMinor = 100;
  bpf_probe_read(&protoMajor, sizeof(protoMajor), req + 0x28);
  bpf_probe_read(&protoMinor, sizeof(protoMinor), req + 0x30);
  struct go_str host = {0};
  bpf_probe_read(&host, sizeof(host), req + 0x80);
  event.host[0] = '\0';
  int len = 0;
  if (host.len > sizeof(event.host) - 1) {
    len = sizeof(event.host) - 1;
  } else {
    len = host.len;
  }

  bpf_probe_read_user(&event.host, len, host.str);
  event.protoMajor = protoMajor;
  event.protoMinor = protoMinor;

  if (bpf_map_update_elem(&traces, &key, &event, BPF_ANY) < 0) {
    bpf_printk("bpf_map_update_elem failed\n");
  }
  return 0;
}

SEC("uprobe/end_trace")
int uprobe_end_trace(struct pt_regs *ctx) {
  bpf_printk("uprobe_end_trace called\n");
  struct event *event;

  __u64 key = goroutine_id(ctx);
  event = bpf_map_lookup_elem(&traces, &key);
  if (event == NULL) {
    return 0;
  }

  event->end_time = bpf_ktime_get_ns();

  if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
                            sizeof(*event)) < 0) {
    bpf_printk("bpf_map_push_elem failed\n");
    return 0;
  }

  if (bpf_map_delete_elem(&traces, &key) < 0) {
    bpf_printk("bpf_map_update_elem failed\n");
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
