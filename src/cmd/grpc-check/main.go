package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	labv1 "sws-lab/internal/gen/sws/lab/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

type result struct {
	Target      string       `json:"target"`
	Health      string       `json:"health"`
	Ping        pingResult   `json:"ping"`
	Echo        echoResult   `json:"echo"`
	WatchEvents []watchEvent `json:"watch_events"`
}

type pingResult struct {
	Message    string `json:"message"`
	AppName    string `json:"app_name"`
	ServerTime string `json:"server_time"`
}

type echoResult struct {
	Value    string            `json:"value"`
	Labels   map[string]string `json:"labels"`
	Executed bool              `json:"executed"`
}

type watchEvent struct {
	Sequence   int32  `json:"sequence"`
	Message    string `json:"message"`
	ServerTime string `json:"server_time"`
}

func main() {
	target := flag.String("target", "127.0.0.1:9090", "gRPC host:port")
	plaintext := flag.Bool("plaintext", false, "connect without TLS")
	timeout := flag.Duration("timeout", 10*time.Second, "overall check timeout")
	value := flag.String("value", "hello over gRPC", "safe value for the Echo call")
	testID := flag.String("test-id", "", "optional X-WAF-Test-ID metadata value for log correlation")
	flag.Parse()

	transportCredentials := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	if *plaintext {
		transportCredentials = insecure.NewCredentials()
	}
	connection, err := grpc.NewClient(*target, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		log.Fatalf("create gRPC client: %v", err)
	}
	defer connection.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if *testID != "" {
		ctx = metadata.AppendToOutgoingContext(
			ctx,
			"x-waf-test-id", *testID,
			"x-request-id", *testID,
		)
	}

	healthResponse, err := healthv1.NewHealthClient(connection).Check(ctx, &healthv1.HealthCheckRequest{
		Service: labv1.LabService_ServiceDesc.ServiceName,
	})
	if err != nil {
		log.Fatalf("health check: %v", err)
	}

	client := labv1.NewLabServiceClient(connection)
	ping, err := client.Ping(ctx, &labv1.PingRequest{})
	if err != nil {
		log.Fatalf("Ping: %v", err)
	}
	echo, err := client.Echo(ctx, &labv1.EchoRequest{
		Value:  *value,
		Labels: map[string]string{"client": "grpc-check"},
	})
	if err != nil {
		log.Fatalf("Echo: %v", err)
	}
	watch, err := client.Watch(ctx, &labv1.WatchRequest{Message: "stream-event", Count: 3, IntervalMs: 100})
	if err != nil {
		log.Fatalf("Watch: %v", err)
	}

	checkResult := result{
		Target: *target,
		Health: healthResponse.GetStatus().String(),
		Ping: pingResult{
			Message:    ping.GetMessage(),
			AppName:    ping.GetAppName(),
			ServerTime: ping.GetServerTime(),
		},
		Echo: echoResult{
			Value:    echo.GetValue(),
			Labels:   echo.GetLabels(),
			Executed: echo.GetExecuted(),
		},
	}
	for {
		event, recvErr := watch.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			log.Fatalf("Watch receive: %v", recvErr)
		}
		checkResult.WatchEvents = append(checkResult.WatchEvents, watchEvent{
			Sequence:   event.GetSequence(),
			Message:    event.GetMessage(),
			ServerTime: event.GetServerTime(),
		})
	}

	encoded, err := json.MarshalIndent(checkResult, "", "  ")
	if err != nil {
		log.Fatalf("encode result: %v", err)
	}
	fmt.Println(string(encoded))
}
