package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
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
	defer uretp.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	rawEvents := make(chan []byte)

	go func() {
		for {
			recode, err := rd.Read()
			if err != nil {
				log.Fatalf("reading from perf event reader: %s", err)
				continue
			}
			if recode.LostSamples != 0 {
				log.Printf("lost %d samples\n", recode.LostSamples)
				continue
			}
			rawEvents <- recode.RawSample
		}
	}()

	for {
		select {
		case <-stopper:
			log.Println("Received signal, exiting...")
			return
		case raw := <-rawEvents:
			var event tracerEvent
			if err := binary.Read(bytes.NewBuffer(raw), binary.LittleEndian, &event); err != nil {
				log.Printf("parsing perf event: %s", err)
				continue
			}
			log.Printf("PID: %d, Duration: %d ns\n", event.Pid, event.EndTime-event.StartTime)
		}
	}
}
