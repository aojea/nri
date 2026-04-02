package stub

import (
	"context"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

type networkHookPlugin struct {
	networkSetupCalled    bool
	networkTeardownCalled bool
	networkCheckCalled    bool
}

func (*networkHookPlugin) RunPodSandbox(context.Context, *api.PodSandbox) error {
	return nil
}

func (p *networkHookPlugin) NetworkSetup(_ context.Context, req *api.NetworkSetupRequest) (*api.NetworkSetupResponse, error) {
	p.networkSetupCalled = true
	return &api.NetworkSetupResponse{Interfaces: req.CurrentInterfaces}, nil
}

func (p *networkHookPlugin) NetworkTeardown(_ context.Context, req *api.NetworkTeardownRequest) (*api.NetworkTeardownResponse, error) {
	p.networkTeardownCalled = true
	_ = req
	return &api.NetworkTeardownResponse{}, nil
}

func (p *networkHookPlugin) NetworkCheck(_ context.Context, req *api.NetworkCheckRequest) (*api.NetworkCheckResponse, error) {
	p.networkCheckCalled = true
	return &api.NetworkCheckResponse{Healthy: true, Reason: req.PodSandboxId}, nil
}

func TestStubNetworkHooksWiredAndDispatched(t *testing.T) {
	plugin := &networkHookPlugin{}
	s, err := New(plugin, WithPluginName("test-plugin"), WithPluginIdx("90"))
	if err != nil {
		t.Fatalf("failed to create stub: %v", err)
	}

	internal := s.(*stub)
	if internal.handlers.NetworkSetup == nil {
		t.Fatalf("NetworkSetup handler not wired")
	}
	if internal.handlers.NetworkTeardown == nil {
		t.Fatalf("NetworkTeardown handler not wired")
	}
	if internal.handlers.NetworkCheck == nil {
		t.Fatalf("NetworkCheck handler not wired")
	}

	if _, err := internal.NetworkSetup(context.Background(), &api.NetworkSetupRequest{PodSandboxId: "pod0"}); err != nil {
		t.Fatalf("NetworkSetup failed: %v", err)
	}
	if _, err := internal.NetworkTeardown(context.Background(), &api.NetworkTeardownRequest{PodSandboxId: "pod0"}); err != nil {
		t.Fatalf("NetworkTeardown failed: %v", err)
	}
	resp, err := internal.NetworkCheck(context.Background(), &api.NetworkCheckRequest{PodSandboxId: "pod0"})
	if err != nil {
		t.Fatalf("NetworkCheck failed: %v", err)
	}
	if !resp.Healthy || resp.Reason != "pod0" {
		t.Fatalf("unexpected NetworkCheck response: %+v", resp)
	}

	if !plugin.networkSetupCalled {
		t.Fatalf("NetworkSetup plugin handler was not called")
	}
	if !plugin.networkTeardownCalled {
		t.Fatalf("NetworkTeardown plugin handler was not called")
	}
	if !plugin.networkCheckCalled {
		t.Fatalf("NetworkCheck plugin handler was not called")
	}
}

type runPodOnlyPlugin struct{}

func (*runPodOnlyPlugin) RunPodSandbox(context.Context, *api.PodSandbox) error {
	return nil
}

func TestStubNetworkHookDefaults(t *testing.T) {
	s, err := New(&runPodOnlyPlugin{}, WithPluginName("test-plugin"), WithPluginIdx("90"))
	if err != nil {
		t.Fatalf("failed to create stub: %v", err)
	}

	internal := s.(*stub)
	resp, err := internal.NetworkCheck(context.Background(), &api.NetworkCheckRequest{})
	if err != nil {
		t.Fatalf("NetworkCheck default failed: %v", err)
	}
	if !resp.Healthy {
		t.Fatalf("default NetworkCheck should be healthy")
	}

	if _, err := internal.NetworkSetup(context.Background(), &api.NetworkSetupRequest{}); err != nil {
		t.Fatalf("default NetworkSetup failed: %v", err)
	}
	if _, err := internal.NetworkTeardown(context.Background(), &api.NetworkTeardownRequest{}); err != nil {
		t.Fatalf("default NetworkTeardown failed: %v", err)
	}
}
