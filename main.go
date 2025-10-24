package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: %s <binary_path> <symbol_name>", os.Args[0])
		return
	}

	binPath := os.Args[1]

	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		log.Fatalf("binary path does not exist: %s", binPath)
		return
	}

	symbol := os.Args[2]
	if symbol == "" {
		log.Fatalf("symbol name is required")
		return
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	objs := tracerObjects{}
	if err := loadTracerObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

	up, err := ex.Uprobe(symbol, objs.UprobeStartTrace, nil)
	if err != nil {
		log.Fatalf("creating uretprobe: %s", err)
	}
	defer up.Close()

	uretp, err := ex.Uretprobe(symbol, objs.UretprobeEndTrace, nil)
	if err != nil {
		log.Fatalf("creating uretprobe: %s", err)
		uretp.Close()
	}

	entries := objs.Events.Iterate()
	var key uint64
	var event tracerEvent
	values := make(map[uint64]tracerEvent, 0)
	for {
		select {
		case <-stopper:
			objs.Close()
			log.Println("Exiting...")
			return
		default:
		}
		for entries.Next(&key, &event) {
			values[key] = event
		}
		if err := entries.Err(); err != nil {
			fmt.Printf("Error iterating map: %v\n", err)
		}
		for k, v := range values {
			fmt.Printf("Goroutine: %d, PID: %d, TID: %d, Start: %d, End: %d\n",
				k, v.Pid, v.Tid, v.StartTime, v.EndTime)
		}
	}
}
