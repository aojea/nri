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

package builtin

import (
	"context"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

func TestBuiltinPluginNetworkHooksDispatch(t *testing.T) {
	setupCalled := false
	teardownCalled := false
	checkCalled := false

	p := &BuiltinPlugin{
		Handlers: BuiltinHandlers{
			NetworkSetup: func(_ context.Context, req *api.NetworkSetupRequest) (*api.NetworkSetupResponse, error) {
				setupCalled = true
				return &api.NetworkSetupResponse{Interfaces: req.CurrentInterfaces}, nil
			},
			NetworkTeardown: func(_ context.Context, req *api.NetworkTeardownRequest) (*api.NetworkTeardownResponse, error) {
				teardownCalled = true
				_ = req
				return &api.NetworkTeardownResponse{}, nil
			},
			NetworkCheck: func(_ context.Context, req *api.NetworkCheckRequest) (*api.NetworkCheckResponse, error) {
				checkCalled = true
				return &api.NetworkCheckResponse{Healthy: true, Reason: req.PodSandboxId}, nil
			},
		},
	}

	if _, err := p.NetworkSetup(context.Background(), &api.NetworkSetupRequest{PodSandboxId: "pod1"}); err != nil {
		t.Fatalf("NetworkSetup failed: %v", err)
	}
	if _, err := p.NetworkTeardown(context.Background(), &api.NetworkTeardownRequest{PodSandboxId: "pod1"}); err != nil {
		t.Fatalf("NetworkTeardown failed: %v", err)
	}
	resp, err := p.NetworkCheck(context.Background(), &api.NetworkCheckRequest{PodSandboxId: "pod1"})
	if err != nil {
		t.Fatalf("NetworkCheck failed: %v", err)
	}
	if !resp.Healthy || resp.Reason != "pod1" {
		t.Fatalf("unexpected NetworkCheck response: %+v", resp)
	}

	if !setupCalled {
		t.Fatalf("NetworkSetup handler was not called")
	}
	if !teardownCalled {
		t.Fatalf("NetworkTeardown handler was not called")
	}
	if !checkCalled {
		t.Fatalf("NetworkCheck handler was not called")
	}
}

func TestBuiltinPluginNetworkHookDefaults(t *testing.T) {
	p := &BuiltinPlugin{}

	if _, err := p.NetworkSetup(context.Background(), &api.NetworkSetupRequest{}); err != nil {
		t.Fatalf("default NetworkSetup failed: %v", err)
	}
	if _, err := p.NetworkTeardown(context.Background(), &api.NetworkTeardownRequest{}); err != nil {
		t.Fatalf("default NetworkTeardown failed: %v", err)
	}
	resp, err := p.NetworkCheck(context.Background(), &api.NetworkCheckRequest{})
	if err != nil {
		t.Fatalf("default NetworkCheck failed: %v", err)
	}
	if !resp.Healthy {
		t.Fatalf("default NetworkCheck should be healthy")
	}
}
