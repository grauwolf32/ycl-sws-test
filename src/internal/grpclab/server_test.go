package grpclab

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	labv1 "sws-lab/internal/gen/sws/lab/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func testClient(t *testing.T) (labv1.LabServiceClient, healthv1.HealthClient) {
	t.Helper()
	return testClientWithLogger(t, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func testClientWithLogger(t *testing.T, logger *slog.Logger) (labv1.LabServiceClient, healthv1.HealthClient) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := NewServer(Config{
		AppName:        "Test Lab",
		MaxDelay:       50 * time.Millisecond,
		MaxRecvMsgSize: 1 << 20,
		Logger:         logger,
	})
	go func() {
		_ = server.Serve(listener)
	}()

	connection, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("create gRPC client: %v", err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
		server.Stop()
		_ = listener.Close()
	})
	return labv1.NewLabServiceClient(connection), healthv1.NewHealthClient(connection)
}

func TestRequestIDIsWrittenToStructuredLog(t *testing.T) {
	var logs bytes.Buffer
	client, _ := testClientWithLogger(t, slog.New(slog.NewJSONHandler(&logs, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "x-request-id", "grpc-correlation-test")

	if _, err := client.Ping(ctx, &labv1.PingRequest{}); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !bytes.Contains(logs.Bytes(), []byte(`"request_id":"grpc-correlation-test"`)) {
		t.Fatalf("gRPC log does not contain request ID: %s", logs.String())
	}
}

func TestPingEchoAndHealth(t *testing.T) {
	client, healthClient := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	healthResponse, err := healthClient.Check(ctx, &healthv1.HealthCheckRequest{Service: labv1.LabService_ServiceDesc.ServiceName})
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	if healthResponse.GetStatus() != healthv1.HealthCheckResponse_SERVING {
		t.Fatalf("health status = %s, want SERVING", healthResponse.GetStatus())
	}

	ping, err := client.Ping(ctx, &labv1.PingRequest{})
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if ping.GetMessage() != "pong" || ping.GetAppName() != "Test Lab" || ping.GetServerTime() == "" {
		t.Fatalf("unexpected Ping response: %#v", ping)
	}

	echo, err := client.Echo(ctx, &labv1.EchoRequest{
		Value:  "<script>waf-test</script>",
		Labels: map[string]string{"source": "unit-test"},
	})
	if err != nil {
		t.Fatalf("Echo: %v", err)
	}
	if echo.GetValue() != "<script>waf-test</script>" || echo.GetLabels()["source"] != "unit-test" || echo.GetExecuted() {
		t.Fatalf("unexpected Echo response: %#v", echo)
	}
}

func TestWatchAndValidation(t *testing.T) {
	client, _ := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Watch(ctx, &labv1.WatchRequest{Message: "event", Count: 3, IntervalMs: 1})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	for wantSequence := int32(1); wantSequence <= 3; wantSequence++ {
		event, recvErr := stream.Recv()
		if recvErr != nil {
			t.Fatalf("receive event %d: %v", wantSequence, recvErr)
		}
		if event.GetSequence() != wantSequence || event.GetMessage() != "event" || event.GetServerTime() == "" {
			t.Fatalf("unexpected event: %#v", event)
		}
	}
	if _, err = stream.Recv(); err != io.EOF {
		t.Fatalf("final stream error = %v, want EOF", err)
	}

	invalidStream, err := client.Watch(ctx, &labv1.WatchRequest{Count: maxWatchCount + 1})
	if err != nil {
		t.Fatalf("open invalid Watch: %v", err)
	}
	if _, err = invalidStream.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid Watch status = %s, want InvalidArgument", status.Code(err))
	}
}
