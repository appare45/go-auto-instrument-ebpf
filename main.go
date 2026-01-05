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
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"
)

type structFieldOffsetVariable struct {
	StructName string
	FieldName  string
	Variable   *ebpf.Variable
}

func (s *structFieldOffsetVariable) getOffset(analyzer *elffunction.ElfFunctionAnalyzer) (int64, error) {
	return analyzer.StructFieldOffset(s.StructName, s.FieldName)
}

func (s *structFieldOffsetVariable) SetVariable(analyzer *elffunction.ElfFunctionAnalyzer) error {
	offset, err := s.getOffset(analyzer)
	if err != nil {
		return err
	}
	log.Printf("Setting offset for %s.%s: %d\n", s.StructName, s.FieldName, offset)
	return s.Variable.Set(uint32(offset))
}

var (
	objs = tracerObjects{}
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

	if err := loadTracerObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	structFieldOffsetVariables := []structFieldOffsetVariable{
		{
			StructName: "net/http.Request",
			FieldName:  "URL",
			Variable:   objs.NetHttpRequestURL_offset,
		},
		{
			StructName: "net/url.URL",
			FieldName:  "Path",
			Variable:   objs.NetUrlURL_PathOffset,
		},
		{
			StructName: "net/http.Request",
			FieldName:  "Method",
			Variable:   objs.NetHttpRequestMethodOffset,
		},
		{
			StructName: "net/http.Request",
			FieldName:  "Host",
			Variable:   objs.NetHttpRequestHostOffset,
		},
		{
			StructName: "net/http.Request",
			FieldName:  "ProtoMajor",
			Variable:   objs.NetHttpRequestProtoOffset,
		},
		{
			StructName: "net/http.Request",
			FieldName:  "ProtoMinor",
			Variable:   objs.NetHttpRequestProtoMinorOffset,
		},
		{
			StructName: "net/http.response",
			FieldName:  "status",
			Variable:   objs.NetHttpResponseStatusCodeOffset,
		},
	}

	for _, v := range structFieldOffsetVariables {
		if err := v.SetVariable(funcAnalyzer); err != nil {
			log.Fatalf("setting offset for %s.%s: %s", v.StructName, v.FieldName, err)
		}
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
