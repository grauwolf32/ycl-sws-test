package lab

import "testing"

func TestGRPCConfig(t *testing.T) {
	for _, key := range []string{"ADDR", "PORT", "GRPC_ADDR"} {
		t.Setenv(key, "")
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig defaults: %v", err)
	}
	if cfg.GRPCAddr != ":9090" {
		t.Fatalf("GRPCAddr = %q, want :9090", cfg.GRPCAddr)
	}

	t.Setenv("GRPC_ADDR", ":9191")
	cfg, err = LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig override: %v", err)
	}
	if cfg.GRPCAddr != ":9191" {
		t.Fatalf("GRPCAddr = %q, want :9191", cfg.GRPCAddr)
	}

	t.Setenv("ADDR", ":9191")
	if _, err = LoadConfig(); err == nil {
		t.Fatal("LoadConfig accepted identical HTTP and gRPC addresses")
	}
}
