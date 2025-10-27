package main

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	elffunction "github.com/appare45/otel-go-auto/elffunction"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"
)

func GetRealTimestamp(timeNanosec int64) (time.Time, error) {
	// 現在時刻・現在のboot offsetを取得し、boot_offset時の時刻を計算する
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		return time.Time{}, err
	}
	offset := time.Nanosecond * time.Duration(now.Nano()-timeNanosec)
	return time.Now().Add(-1 * offset), nil
}

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: %s <binary_path> <symbol_name>", os.Args[0])
		return
	}

	binPath := os.Args[1]
	symbol := os.Args[2]
	if symbol == "" {
		log.Fatalf("symbol name is required")
		return
	}

	fd, err := os.Open(binPath)
	if err != nil {
		log.Fatalf("opening binary file: %s", err)
	}
	defer fd.Close()

	elffile, err := elf.NewFile(fd)
	if err != nil {
		log.Fatalf("parsing ELF file: %s", err)
	}

	funcAnalyzer, err := elffunction.NewAnalyzer(elffile)
	symbolOffset, symbolRetOffsets, err := funcAnalyzer.Get(symbol)
	if err != nil {
		log.Fatalf("finding symbol %s: %s", symbol, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	objs := tracerObjects{}
	if err := loadTracerObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		log.Fatalf("opening executable: %s", err)
	}

	probes, err := probeFunc(ex, objs.UprobeStartTrace, objs.UprobeEndTrace, symbolOffset, symbolRetOffsets)
	if err != nil {
		log.Fatalf("setting up probes: %s", err)
	}
	defer func() {
		for _, p := range probes {
			p.Close()
		}
	}()

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

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ctx := context.Background()
	stopOtel, err := initTracerProvider(ctx, binPath)
	defer stopOtel(ctx)
	tracer := otel.GetTracerProvider().Tracer("github.com/appare45/otel-go-auto")

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
			starttime, err := GetRealTimestamp(int64(event.StartTime))
			if err != nil {
				log.Printf("getting real timestamp: %s", err)
				continue
			}
			endTime, err := GetRealTimestamp(int64(event.EndTime))
			if err != nil {
				log.Printf("getting real timestamp: %s", err)
				continue
			}

			log.Printf("Function %s executed with param %d Duration: %d ms\n", symbol, event.Param1, endTime.Sub(starttime).Milliseconds())

			_, span := tracer.Start(context.TODO(), fmt.Sprintf("uprobe: %s", symbol), trace.WithTimestamp(starttime))
			span.End(trace.WithTimestamp(endTime))
		}
	}
}
