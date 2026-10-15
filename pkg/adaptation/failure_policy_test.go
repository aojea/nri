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

package adaptation_test

import (
	"context"
	stdnet "net"
	"sync"
	"testing"
	"time"

	"github.com/containerd/ttrpc"
	"github.com/stretchr/testify/require"

	nri "github.com/containerd/nri/pkg/adaptation"
	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

// requestTimeout is the plugin request timeout used by the tests in this
// file. It is deliberately short to keep the tests fast: plugins that need
// to exceed it simply block until released.
const requestTimeout = 100 * time.Millisecond

// blocker is a plugin request handler which blocks until released. Requests
// arriving after Release() are handled immediately.
type blocker struct {
	release chan struct{}
	done    chan struct{}
	once    sync.Once
}

func newBlocker(t *testing.T) *blocker {
	t.Helper()
	b := &blocker{
		release: make(chan struct{}),
		done:    make(chan struct{}),
	}
	// Never leave a plugin blocked once the test is over.
	t.Cleanup(b.Release)
	return b
}

// handle blocks until released, then marks the blocked request as done.
func (b *blocker) handle() error {
	<-b.release
	b.once.Do(func() { close(b.done) })
	return nil
}

// Release unblocks the handler.
func (b *blocker) Release() {
	select {
	case <-b.release:
	default:
		close(b.release)
	}
}

// WaitDone waits for the blocked request handler to return. This establishes
// a happens-before relation between the blocked handler and anything the
// test does next (for instance, sending another request to the plugin).
func (b *blocker) WaitDone(t *testing.T) {
	t.Helper()
	select {
	case <-b.done:
	case <-time.After(startupTimeout):
		t.Fatal("timed out waiting for the blocked request handler to return")
	}
}

// requestCase describes how to block a plugin for, issue, and recognize a
// request of a given type.
type requestCase struct {
	name    string
	block   func(p *mockPlugin, b *blocker)
	request func(pod *api.PodSandbox, ctr *api.Container) error
	event   func(pod *api.PodSandbox, ctr *api.Container) *Event
}

func TestPluginFailurePolicy(t *testing.T) {
	s := &Suite{}

	setup := func(t *testing.T, plugins ...*mockPlugin) {
		t.Helper()
		nri.SetPluginRequestTimeout(requestTimeout)
		t.Cleanup(func() {
			nri.SetPluginRequestTimeout(nri.DefaultPluginRequestTimeout)
		})
		s.Prepare(t, &mockRuntime{}, plugins...)
	}

	var (
		ctx  = context.Background()
		pod0 = &api.PodSandbox{Id: "pod0", Name: "pod0", Uid: "uid0", Namespace: "default"}
		pod1 = &api.PodSandbox{Id: "pod1", Name: "pod1", Uid: "uid1", Namespace: "default"}
		ctr0 = &api.Container{Id: "ctr0", PodSandboxId: "pod0", Name: "ctr0", State: api.ContainerState_CONTAINER_CREATED}
		ctr1 = &api.Container{Id: "ctr1", PodSandboxId: "pod0", Name: "ctr1", State: api.ContainerState_CONTAINER_CREATED}

		// The four possible policies. The zero value is the historical
		// behavior and what plugins without a policy get.
		dropAndProceed = &api.FailurePolicy{}
		dropAndFail    = &api.FailurePolicy{FailRequest: true}
		keepAndProceed = &api.FailurePolicy{KeepConnected: true}
		keepAndFail    = &api.FailurePolicy{FailRequest: true, KeepConnected: true}

		// A plugin subscribed to the events exercised below only (and in
		// particular not acting as a validator), with the given policy. A
		// nil policy leaves the plugin without one.
		newPlugin = func(idx, name string, policy *api.FailurePolicy) *mockPlugin {
			p := &mockPlugin{
				idx:  idx,
				name: name,
				mask: api.MustParseEventMask("RunPodSandbox", "CreateContainer"),
			}
			if policy != nil {
				p.options = []stub.Option{stub.WithFailurePolicy(policy)}
			}
			return p
		}

		requests = []requestCase{
			{
				name: "RunPodSandbox",
				block: func(p *mockPlugin, b *blocker) {
					p.runPodSandbox = func(*mockPlugin, *api.PodSandbox, *api.Container) error {
						return b.handle()
					}
				},
				request: func(pod *api.PodSandbox, _ *api.Container) error {
					return s.runtime.RunPodSandbox(ctx, &api.RunPodSandboxRequest{Pod: pod})
				},
				event: func(pod *api.PodSandbox, _ *api.Container) *Event {
					return PodSandboxEvent(pod, RunPodSandbox)
				},
			},
			{
				name: "CreateContainer",
				block: func(p *mockPlugin, b *blocker) {
					p.createContainer = func(*mockPlugin, *api.PodSandbox, *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
						return nil, nil, b.handle()
					}
				},
				request: func(pod *api.PodSandbox, ctr *api.Container) error {
					_, err := s.runtime.CreateContainer(ctx, &api.CreateContainerRequest{Pod: pod, Container: ctr})
					return err
				},
				event: func(_ *api.PodSandbox, ctr *api.Container) *Event {
					return ContainerEvent(ctr, CreateContainer)
				},
			},
		}
	)

	// The default policy: a plugin exceeding the request timeout is dropped
	// and the request proceeds without it. The runtime never sees the timeout
	// (containerd/nri#316, #142, #114, #90, #273). Plugins without a policy
	// and plugins with an all-default one are treated the same.
	t.Run("default: a timed out plugin is dropped and the request proceeds without it", func(t *testing.T) {
		for _, policy := range []struct {
			name   string
			policy *api.FailurePolicy
		}{
			{name: "no policy", policy: nil},
			{name: "zero policy", policy: dropAndProceed},
		} {
			for _, tc := range requests {
				t.Run(policy.name+"/"+tc.name, func(t *testing.T) {
					var (
						b    = newBlocker(t)
						slow = newPlugin("00", "slow", policy.policy)
						next = newPlugin("10", "next", nil)
					)
					tc.block(slow, b)
					setup(t, slow, next)
					s.Startup()

					require.NoError(t, tc.request(pod0, ctr0))
					// The timed out plugin gets disconnected by the runtime...
					require.NoError(t, slow.Wait(PluginDisconnected, time.After(startupTimeout)))
					// ...and the remaining plugins are still invoked.
					require.NoError(t, next.Wait(tc.event(pod0, ctr0), time.After(startupTimeout)))
				})
			}
		}
	})

	// FailRequest without KeepConnected: the request fails and the plugin
	// is dropped, as it would be by default.
	t.Run("fail_request: a timed out plugin fails the request and is dropped", func(t *testing.T) {
		for _, tc := range requests {
			t.Run(tc.name, func(t *testing.T) {
				var (
					b    = newBlocker(t)
					slow = newPlugin("00", "slow", dropAndFail)
					next = newPlugin("10", "next", nil)
				)
				tc.block(slow, b)
				setup(t, slow, next)
				s.Startup()

				err := tc.request(pod0, ctr0)
				require.ErrorIs(t, err, context.DeadlineExceeded)
				require.ErrorContains(t, err, slow.FullName())
				require.ErrorContains(t, err, tc.name)
				require.False(t, next.EventQ().Has(tc.event(pod0, ctr0)))
				require.NoError(t, slow.Wait(PluginDisconnected, time.After(startupTimeout)))
			})
		}
	})

	// KeepConnected without FailRequest: the request proceeds without the
	// plugin, as it would by default, but the plugin is not dropped for
	// being slow once and handles further requests.
	t.Run("keep_connected: a timed out plugin stays connected and the request proceeds without it", func(t *testing.T) {
		for _, tc := range requests {
			t.Run(tc.name, func(t *testing.T) {
				var (
					b    = newBlocker(t)
					slow = newPlugin("00", "slow", keepAndProceed)
					next = newPlugin("10", "next", nil)
				)
				tc.block(slow, b)
				setup(t, slow, next)
				s.Startup()

				require.NoError(t, tc.request(pod0, ctr0))
				require.NoError(t, next.Wait(tc.event(pod0, ctr0), time.After(startupTimeout)))

				b.Release()
				b.WaitDone(t)
				require.NoError(t, tc.request(pod1, ctr1))
				require.NoError(t, slow.Wait(tc.event(pod1, ctr1), time.After(startupTimeout)))
				require.NoError(t, next.Wait(tc.event(pod1, ctr1), time.After(startupTimeout)))
				require.False(t, slow.EventQ().Has(PluginDisconnected))
			})
		}
	})

	// FailRequest and KeepConnected: only this request failed. The failure
	// is reported to the runtime like any other plugin error and the plugin
	// keeps receiving further requests.
	t.Run("fail_request+keep_connected: a timed out plugin fails the request and stays connected", func(t *testing.T) {
		for _, tc := range requests {
			t.Run(tc.name, func(t *testing.T) {
				var (
					b    = newBlocker(t)
					slow = newPlugin("00", "slow", keepAndFail)
					next = newPlugin("10", "next", nil)
				)
				tc.block(slow, b)
				setup(t, slow, next)
				s.Startup()

				// The request fails with the timeout, naming the culprit...
				err := tc.request(pod0, ctr0)
				require.ErrorIs(t, err, context.DeadlineExceeded)
				require.ErrorContains(t, err, slow.FullName())
				require.ErrorContains(t, err, tc.name)
				// ...and, as for any other plugin error, the remaining plugins
				// are not invoked for it.
				require.False(t, next.EventQ().Has(tc.event(pod0, ctr0)))

				// The plugin is neither disconnected nor unregistered: once it
				// is responsive again it handles further requests normally.
				b.Release()
				b.WaitDone(t)
				require.NoError(t, tc.request(pod1, ctr1))
				require.NoError(t, slow.Wait(tc.event(pod1, ctr1), time.After(startupTimeout)))
				require.NoError(t, next.Wait(tc.event(pod1, ctr1), time.After(startupTimeout)))
				require.False(t, slow.EventQ().Has(PluginDisconnected))
			})
		}
	})

	// Validators always fail the request on any error. KeepConnected still
	// decides whether a timed out validator is dropped.
	t.Run("keep_connected: a timed out validator fails the request and stays connected", func(t *testing.T) {
		var (
			b         = newBlocker(t)
			validator = &mockPlugin{
				idx:     "00",
				name:    "validator",
				options: []stub.Option{stub.WithFailurePolicy(keepAndProceed)},
			}
		)
		validator.validateAdjustment = func(*mockPlugin, *api.ValidateContainerAdjustmentRequest) error {
			return b.handle()
		}
		setup(t, validator)
		s.Startup()

		require.NoError(t, s.runtime.RunPodSandbox(ctx, &api.RunPodSandboxRequest{Pod: pod0}))

		_, err := s.runtime.CreateContainer(ctx, &api.CreateContainerRequest{Pod: pod0, Container: ctr0})
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.ErrorContains(t, err, validator.FullName())

		b.Release()
		b.WaitDone(t)
		_, err = s.runtime.CreateContainer(ctx, &api.CreateContainerRequest{Pod: pod0, Container: ctr1})
		require.NoError(t, err)
		require.NoError(t, validator.Wait(ContainerEvent(ctr1, ValidateContainerAdjustment), time.After(startupTimeout)))
		require.False(t, validator.EventQ().Has(PluginDisconnected))
	})

	// Losing the connection is a different matter: the plugin is gone and is
	// dropped whatever KeepConnected says. FailRequest alone decides whether
	// the request proceeds without it or fails.
	t.Run("a plugin disconnected during a request is dropped", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			policy  *api.FailurePolicy
			wantErr bool
		}{
			{name: "no policy: the request proceeds without it", policy: nil},
			{name: "keep_connected: the request proceeds without it", policy: keepAndProceed},
			{name: "fail_request: the request fails", policy: dropAndFail, wantErr: true},
			{name: "fail_request+keep_connected: the request fails", policy: keepAndFail, wantErr: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var (
					conn  stdnet.Conn
					crash = newPlugin("00", "crash", tc.policy)
					next  = newPlugin("10", "next", nil)
				)
				// Capture the plugin's connection so the request handler can
				// close it, emulating the plugin dying mid-request.
				crash.options = append(crash.options,
					stub.WithDialer(func(path string) (stdnet.Conn, error) {
						c, err := stdnet.Dial("unix", path)
						conn = c
						return c, err
					}),
				)
				crash.runPodSandbox = func(*mockPlugin, *api.PodSandbox, *api.Container) error {
					return conn.Close()
				}
				setup(t, crash, next)
				s.Startup()

				err := s.runtime.RunPodSandbox(ctx, &api.RunPodSandboxRequest{Pod: pod0})
				require.NoError(t, crash.Wait(PluginDisconnected, time.After(startupTimeout)))

				if tc.wantErr {
					require.ErrorIs(t, err, ttrpc.ErrClosed)
					require.ErrorContains(t, err, crash.FullName())
					require.False(t, next.EventQ().Has(PodSandboxEvent(pod0, RunPodSandbox)))
				} else {
					require.NoError(t, err)
					require.NoError(t, next.Wait(PodSandboxEvent(pod0, RunPodSandbox), time.After(startupTimeout)))
				}
			})
		}
	})

	// A deadline set by the runtime on the whole operation is not a plugin
	// failure: the plugin is not dropped for it whatever its policy, and
	// the runtime gets its own deadline error back unchanged.
	t.Run("a runtime deadline during a request is not a plugin failure", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			policy *api.FailurePolicy
		}{
			{name: "no policy", policy: nil},
			{name: "fail_request", policy: dropAndFail},
			{name: "fail_request+keep_connected", policy: keepAndFail},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var (
					b    = newBlocker(t)
					slow = newPlugin("00", "slow", tc.policy)
					next = newPlugin("10", "next", nil)
				)
				slow.runPodSandbox = func(*mockPlugin, *api.PodSandbox, *api.Container) error {
					return b.handle()
				}
				setup(t, slow, next)
				s.Startup()

				// The runtime's deadline is well below the NRI request timeout.
				rctx, cancel := context.WithTimeout(ctx, requestTimeout/4)
				defer cancel()
				err := s.runtime.RunPodSandbox(rctx, &api.RunPodSandboxRequest{Pod: pod0})
				require.ErrorIs(t, err, context.DeadlineExceeded)
				require.NotContains(t, err.Error(), slow.FullName())
				require.False(t, next.EventQ().Has(PodSandboxEvent(pod0, RunPodSandbox)))

				// The plugin is still registered and handles further requests.
				b.Release()
				b.WaitDone(t)
				require.NoError(t, s.runtime.RunPodSandbox(ctx, &api.RunPodSandboxRequest{Pod: pod1}))
				require.NoError(t, slow.Wait(PodSandboxEvent(pod1, RunPodSandbox), time.After(startupTimeout)))
				require.False(t, slow.EventQ().Has(PluginDisconnected))
			})
		}
	})

	t.Run("a nil failure policy is rejected by the stub", func(t *testing.T) {
		_, err := stub.New(&mockPlugin{},
			stub.WithPluginName("test"),
			stub.WithPluginIdx("00"),
			stub.WithFailurePolicy(nil),
		)
		require.Error(t, err)
	})
}
