package main

import (
	"context"
	"log"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

const otelSdkName = "my-otel-ebpf-app"

func initTracerProvider(ctx context.Context, serviceName string) (func(context.Context) error, error) {
	apikey := os.Getenv("MACKEREL_API_KEY")
	if apikey == "" {
		log.Println("MACKEREL_API_KEY is not set, skipping tracer initialization")
		return nil, nil
	}
	client := otlptracehttp.NewClient(
		otlptracehttp.WithEndpoint("otlp-vaxila.mackerelio.com"),
		otlptracehttp.WithHeaders(map[string]string{
			"Accept":           "*/*",
			"Mackerel-Api-Key": apikey,
		}),
		otlptracehttp.WithCompression(otlptracehttp.GzipCompression),
	)

	otlpExporter, err := otlptrace.New(ctx, client)
	if err != nil {
		return nil, err
	}
	stdoutExporter, err := stdouttrace.New()
	if err != nil {
		return nil, err
	}

	resources, err := resource.New(
		ctx,
		resource.WithHost(),
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.TelemetrySDKName(otelSdkName),
		),
	)
	if err != nil {
		return nil, err
	}

	tp := trace.NewTracerProvider(
		trace.WithBatcher(otlpExporter),
		trace.WithBatcher(stdoutExporter),
		trace.WithResource(resources),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}
