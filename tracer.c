// go:build ignore

#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>

struct event {
  __u32 pid;
  __u32 tid;
  __u64 goroutine;
  __u64 start_time;
  __u64 end_time;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64); // goroutine ID as key
  __type(value, struct event);
  __uint(max_entries, 1024);
} events SEC(".maps");

#if defined(bpf_target_arm64)
// https://go.dev/src/cmd/compile/abi-internal#arm64-architecture
#define goroutine_id(ctx) (__PT_REGS_CAST(ctx)->regs[28])
#elif defined(bpf_target_x86)
// https://go.dev/src/cmd/compile/abi-internal#amd64-architecture
// 動くかわからないので注意
#define goroutine_id(ctx) (__PT_REGS_CAST(ctx)->regs[14])
#endif

SEC("uprobe/start_trace")
int uprobe_start_trace(struct pt_regs *ctx) {
  struct event event = {};
  __u64 key = goroutine_id(ctx);

  event.tid = bpf_get_current_pid_tgid();
  event.pid = bpf_get_current_pid_tgid() >> 32;
  event.goroutine = key;
  event.start_time = bpf_ktime_get_ns();

  if (bpf_map_update_elem(&events, &key, &event, BPF_ANY) < 0) {
    bpf_printk("bpf_map_update_elem failed\n");
  }
  return 0;
}

SEC("uretprobe/end_trace")
int uretprobe_end_trace(struct pt_regs *ctx) {
  struct event *event;

  __u64 key = goroutine_id(ctx);
  event = bpf_map_lookup_elem(&events, &key);
  if (event == NULL) {
    return 0;
  }

  event->end_time = bpf_ktime_get_ns();

  if (bpf_map_update_elem(&events, &key, event, BPF_ANY) < 0) {
    bpf_printk("bpf_map_update_elem failed\n");
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
