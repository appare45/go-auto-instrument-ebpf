.PHONY: lima-up lima-down vmlinux.h

LIMA_VM_NAME := otel-go-auto

lima-up:
	@if [ -d "$$HOME/.lima/$(LIMA_VM_NAME)" ]; then \
	  echo "Lima VM '$(LIMA_VM_NAME)' already exists. Skipping create."; \
	else \
	  limactl create --name=$(LIMA_VM_NAME) ./lima.yaml; \
	fi
	limactl start $(LIMA_VM_NAME)

lima-down:
	@if [ ! -d "$$HOME/.lima/$(LIMA_VM_NAME)" ]; then \
	  echo "Lima VM '$(LIMA_VM_NAME)' does not exist. Skipping stop/delete."; \
	  exit 0; \
	fi
	limactl stop $(LIMA_VM_NAME)
	limactl delete $(LIMA_VM_NAME)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

demo:
	sudo ./go-auto-instrument-ebpf ./examples/demo/demo main.main
