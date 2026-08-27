// Package grpclab implements the gRPC side of the SWS test application.
package grpclab

import (
	"context"
	"io"
	"log/slog"
	"maps"
	"runtime/debug"
	"strings"
	"time"

	labv1 "sws-lab/internal/gen/sws/lab/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

const (
	defaultMaxRecvMsgSize = 1 << 20
	defaultWatchCount     = 3
	maxWatchCount         = 20
)

// Config contains the runtime settings needed by the gRPC server.
type Config struct {
	AppName        string
	MaxDelay       time.Duration
	MaxRecvMsgSize int
	Logger         *slog.Logger
}

// NewServer creates a gRPC server with the lab API, standard health service,
// reflection, bounded request sizes, panic recovery, and structured logging.
func NewServer(cfg Config) *grpc.Server {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	maxRecvMsgSize := cfg.MaxRecvMsgSize
	if maxRecvMsgSize <= 0 {
		maxRecvMsgSize = defaultMaxRecvMsgSize
	}

	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxRecvMsgSize),
		grpc.ChainUnaryInterceptor(unaryLoggingInterceptor(logger)),
		grpc.ChainStreamInterceptor(streamLoggingInterceptor(logger)),
	)
	labv1.RegisterLabServiceServer(server, &service{
		appName:  cfg.AppName,
		maxDelay: cfg.MaxDelay,
	})

	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus(labv1.LabService_ServiceDesc.ServiceName, healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(server, healthServer)
	reflection.Register(server)

	return server
}

type service struct {
	labv1.UnimplementedLabServiceServer
	appName  string
	maxDelay time.Duration
}

func (s *service) Ping(context.Context, *labv1.PingRequest) (*labv1.PingResponse, error) {
	return &labv1.PingResponse{
		Message:    "pong",
		AppName:    s.appName,
		ServerTime: time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func (s *service) Echo(_ context.Context, request *labv1.EchoRequest) (*labv1.EchoResponse, error) {
	return &labv1.EchoResponse{
		Value:    request.GetValue(),
		Labels:   maps.Clone(request.GetLabels()),
		Executed: false,
	}, nil
}

func (s *service) Watch(request *labv1.WatchRequest, stream grpc.ServerStreamingServer[labv1.WatchEvent]) error {
	count := request.GetCount()
	if count == 0 {
		count = defaultWatchCount
	}
	if count < 1 || count > maxWatchCount {
		return status.Errorf(codes.InvalidArgument, "count must be between 1 and %d", maxWatchCount)
	}

	interval := time.Duration(request.GetIntervalMs()) * time.Millisecond
	if request.GetIntervalMs() < 0 || interval > s.maxDelay {
		return status.Errorf(codes.InvalidArgument, "interval_ms must be between 0 and %d", s.maxDelay.Milliseconds())
	}
	message := request.GetMessage()
	if message == "" {
		message = "tick"
	}

	for sequence := int32(1); sequence <= count; sequence++ {
		if err := stream.Send(&labv1.WatchEvent{
			Sequence:   sequence,
			Message:    message,
			ServerTime: time.Now().UTC().Format(time.RFC3339Nano),
		}); err != nil {
			return err
		}
		if sequence == count || interval == 0 {
			continue
		}

		timer := time.NewTimer(interval)
		select {
		case <-timer.C:
		case <-stream.Context().Done():
			if !timer.Stop() {
				<-timer.C
			}
			return status.FromContextError(stream.Context().Err()).Err()
		}
	}
	return nil
}

func unaryLoggingInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		request any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (response any, err error) {
		started := time.Now()
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.Error("gRPC panic recovered", "method", info.FullMethod, "panic", recovered, "stack", string(debug.Stack()))
				err = status.Error(codes.Internal, "internal server error")
			}
			if err == nil && isALBGRPCHealthCheck(ctx, info.FullMethod) {
				return
			}
			logger.Info("gRPC request",
				"request_id", firstMetadataValue(ctx, "x-request-id"),
				"method", info.FullMethod,
				"status", status.Code(err).String(),
				"duration_ms", time.Since(started).Milliseconds(),
				"client", grpcClient(ctx),
				"user_agent", firstMetadataValue(ctx, "user-agent"),
			)
		}()
		return handler(ctx, request)
	}
}

func streamLoggingInterceptor(logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(
		server any,
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) (err error) {
		started := time.Now()
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.Error("gRPC panic recovered", "method", info.FullMethod, "panic", recovered, "stack", string(debug.Stack()))
				err = status.Error(codes.Internal, "internal server error")
			}
			if err == nil && isALBGRPCHealthCheck(stream.Context(), info.FullMethod) {
				return
			}
			logger.Info("gRPC request",
				"request_id", firstMetadataValue(stream.Context(), "x-request-id"),
				"method", info.FullMethod,
				"status", status.Code(err).String(),
				"duration_ms", time.Since(started).Milliseconds(),
				"client", grpcClient(stream.Context()),
				"user_agent", firstMetadataValue(stream.Context(), "user-agent"),
			)
		}()
		return handler(server, stream)
	}
}

func grpcClient(ctx context.Context) string {
	if forwardedFor := firstMetadataValue(ctx, "x-forwarded-for"); forwardedFor != "" {
		return strings.TrimSpace(strings.Split(forwardedFor, ",")[0])
	}
	if remotePeer, ok := peer.FromContext(ctx); ok && remotePeer.Addr != nil {
		return remotePeer.Addr.String()
	}
	return ""
}

func firstMetadataValue(ctx context.Context, key string) string {
	values := metadata.ValueFromIncomingContext(ctx, key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func isALBGRPCHealthCheck(ctx context.Context, method string) bool {
	return method == healthv1.Health_Check_FullMethodName &&
		firstMetadataValue(ctx, "user-agent") == "Envoy/HC" &&
		firstMetadataValue(ctx, "x-forwarded-for") == ""
}
