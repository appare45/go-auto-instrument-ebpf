// go:build ignore

#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>

struct event {
  __u32 pid;
  __u32 tid;
  __u64 goroutine;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __type(value, struct event);
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
  struct event event;

  event.tid = bpf_get_current_pid_tgid();
  event.pid = bpf_get_current_pid_tgid() >> 32;
  event.goroutine = goroutine_id(ctx);

  if (bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event,
                            sizeof(event)) < 0) {
    bpf_printk("bpf_perf_event_output failed\n");
  }

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
