/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/containerd/containerd/v2/cmd/ctr/app"
	"github.com/urfave/cli/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

var pluginCmds = []*cli.Command{}

func main() {
    setDefaultOTelEnv()
    shutdown := initTracing()
    if shutdown != nil {
        defer func() {
            ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
            defer cancel()
            _ = shutdown(ctx)
        }()
    }
	app := app.New()
	app.Commands = append(app.Commands, pluginCmds...)
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "ctr: %s\n", err)
		os.Exit(1)
	}
}

// setDefaultOTelEnv provides default OTEL env vars if they are not already set.
// Values provided by the user env take precedence.
func setDefaultOTelEnv() {
    setDefaultEnv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:5445")
    setDefaultEnv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
    setDefaultEnv("OTEL_SERVICE_NAME", "containerd")
    setDefaultEnv("OTEL_TRACES_SAMPLER", "traceidratio")
    setDefaultEnv("OTEL_TRACES_SAMPLER_ARG", "1.0")
}

func setDefaultEnv(key, val string) {
    if _, ok := os.LookupEnv(key); !ok {
        os.Setenv(key, val)
    }
}

// initTracing initializes a global OTEL tracer provider using environment
// variables. Returns a shutdown function or nil if initialization is skipped.
func initTracing() func(ctx context.Context) error {
    // Respect standard envs: if neither endpoint nor traces endpoint is set,
    // skip initialization quietly.
    if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" {
        return nil
    }

    // Choose protocol based on env, default to http/protobuf.
    protocol := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
    if protocol == "" {
        protocol = os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
    }

    // Create exporter from env configuration.
    var (
        exp *otlptrace.Exporter
        err error
    )
    switch protocol {
    case "", "http/protobuf":
        exp, err = otlptracehttp.New(context.Background())
    case "grpc":
        exp, err = otlptracegrpc.New(context.Background())
    default:
        // Fallback to http/protobuf if an unknown protocol is provided.
        exp, err = otlptracehttp.New(context.Background())
    }
    if err != nil {
        return nil
    }

    // Configure provider with a batch span processor. Sampler can be set via env.
    tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
    otel.SetTracerProvider(tp)
    otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

    return tp.Shutdown
}
