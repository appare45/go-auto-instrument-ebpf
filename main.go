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

	elffunction "github.com/appare45/go-auto-instrument-ebpf/elffunction"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName = "github.com/appare45/go-auto-instrument-ebpf"
)

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

	if offset, err := funcAnalyzer.StructFieldOffset("net/http.Request", "URL"); err == nil {
		if err = objs.NetHttpRequestURL_offset.Set(uint32(offset)); err != nil {
			log.Fatalf("setting url offset: %s", err)
		}
	} else {
		log.Fatalf("finding offset of net/http.Request.URL: %s", err)
	}

	if offset, err := funcAnalyzer.StructFieldOffset("net/url.URL", "Path"); err == nil {
		if err = objs.NetUrlURL_PathOffset.Set(uint32(offset)); err != nil {
			log.Fatalf("setting path offset: %s", err)
		}
	} else {
		log.Fatalf("finding offset of net/url.URL.Path: %s", err)
	}

	if offset, err := funcAnalyzer.StructFieldOffset("net/http.Request", "Method"); err == nil {
		if err = objs.NetHttpRequestMethodOffset.Set(uint32(offset)); err != nil {
			log.Fatalf("setting method offset: %s", err)
		}
	} else {
		log.Fatalf("finding offset of net/http.Request.Method: %s", err)
	}

	if offset, err := funcAnalyzer.StructFieldOffset("net/http.Request", "Host"); err == nil {
		if err = objs.NetHttpRequestHostOffset.Set(uint32(offset)); err != nil {
			log.Fatalf("setting host offset: %s", err)
		}
	} else {
		log.Fatalf("finding offset of net/http.Request.Host: %s", err)
	}

	if offset, err := funcAnalyzer.StructFieldOffset("net/http.Request", "ProtoMajor"); err == nil {
		if err = objs.NetHttpRequestProtoOffset.Set(uint32(offset)); err != nil {
			log.Fatalf("setting proto major offset: %s", err)
		}
	} else {
		log.Fatalf("finding offset of net/http.Request.ProtoMajor: %s", err)
	}

	if offset, err := funcAnalyzer.StructFieldOffset("net/http.Request", "ProtoMinor"); err == nil {
		if err = objs.NetHttpRequestProtoMinorOffset.Set(uint32(offset)); err != nil {
			log.Fatalf("setting proto minor offset: %s", err)
		}
	} else {
		log.Fatalf("finding offset of net/http.Request.ProtoMinor: %s", err)
	}

	if offset, err := funcAnalyzer.StructFieldOffset("net/http.Response", "StatusCode"); err == nil {
		if err = objs.NetHttpResponseStatusCodeOffset.Set(uint32(offset)); err != nil {
			log.Fatalf("setting status code offset: %s", err)
		}
	} else {
		log.Fatalf("finding offset of net/http.Response.StatusCode: %s", err)
	}

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

	serviceName := os.Getenv("OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = "ebpf-auto-instrumentation" + binPath
	}

	ctx := context.Background()
	stopOtel, err := initTracerProvider(ctx, serviceName)
	defer stopOtel(ctx)
	tracer := otel.GetTracerProvider().Tracer(tracerName)

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
			fmt.Printf("%+v\n", event)
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

			// Convert event.Host ([256]int8) to string for printing
			hostStr := ""
			for _, c := range event.Host {
				if c == 0 {
					break
				}
				hostStr += string(byte(c))
			}

			pathStr := ""
			for _, c := range event.Path {
				if c == 0 {
					break
				}
				pathStr += string(byte(c))
			}

			methodStr := ""
			for _, c := range event.Method {
				if c == 0 {
					break
				}
				methodStr += string(byte(c))
			}

			log.Printf("Function %s executed Protocol: %d.%d Host %s Path %s Method %s Duration: %d ms Status: %d\n", symbol, event.ProtoMajor, event.ProtoMinor, hostStr, pathStr, methodStr, endTime.Sub(starttime).Milliseconds(), event.StatusCode)

			_, span := tracer.Start(context.TODO(), fmt.Sprintf("%s: %s", methodStr, pathStr),
				trace.WithTimestamp(starttime),
				trace.WithAttributes(
					semconv.HTTPRoute(pathStr),
					semconv.HostName(hostStr),
					semconv.HTTPResponseStatusCode(int(event.StatusCode)),
					attribute.String(string(semconv.HTTPRequestMethodKey), methodStr),
				),
			)
			span.End(trace.WithTimestamp(endTime))
		}
	}
}
