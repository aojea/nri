# NRI Network Lifecycle Hooks

This document describes the pod-scoped network lifecycle hooks added to the NRI Plugin API:

- `NetworkSetup`
- `NetworkTeardown`
- `NetworkCheck`

The protocol-level contract is defined in [pkg/api/api.proto](../pkg/api/api.proto).

## Scope and Motivation

Traditional NRI hooks are mostly container-scoped. Pod networking, however, is tied to the Pod sandbox network namespace.

These hooks are therefore **pod-scoped** and keyed by `pod_sandbox_id`.

### Pod vs. Container Scope

Network lifecycle hooks do not target a `container_id`. They target the pod sandbox boundary:

- The runtime creates the pod network namespace.
- NRI plugins participate in network setup and teardown for that namespace.
- Containers in the pod consume the resulting interfaces.

This avoids the container/pod granularity mismatch for shared pod network namespaces.

## Hook Semantics

### `NetworkSetup`

`NetworkSetup` is called sequentially for registered plugins after the pod network namespace exists and before pod containers are started.

The request includes:

- `pod_sandbox_id`
- `netns_path`
- `annotations`
- `current_interfaces`

`current_interfaces` carries accumulated state from earlier plugins in the chain.

The response returns `interfaces`, representing the total updated interface state after this plugin.

### `NetworkTeardown`

`NetworkTeardown` is called during pod deletion, before network namespace removal.

Execution order is reverse setup order.

The request includes the same pod identity and annotation context and carries `current_interfaces` so teardown can be performed using the last known safe aggregate state.

Plugins are expected to implement teardown idempotently.

### `NetworkCheck`

`NetworkCheck` is an active health/consistency probe.

It allows runtimes to verify detailed network invariants, including interface presence, addresses, MACs, and routes.

The request includes `expected_interfaces` and the response reports `healthy` plus an optional `reason`.

## Runtime State Machine

Runtimes should follow this state model for pod networking.

### 1. Host-network bypass

If a pod uses host networking, network lifecycle hooks must not be called.

### 2. Setup pipeline

For non-host-network pods:

1. Runtime creates pod network namespace.
2. Runtime calls `NetworkSetup` in plugin order.
3. Each plugin receives `current_interfaces` from previous plugins.
4. Each plugin returns updated aggregate interfaces.
5. Runtime passes returned state to the next plugin.

### 3. Rollback on setup failure

If any `NetworkSetup` call fails:

1. Runtime stops forward execution.
2. Runtime invokes `NetworkTeardown` in reverse order for plugins that already completed setup.
3. Runtime passes accumulated safe `current_interfaces` state to teardown.
4. Runtime treats teardown as best-effort and expects plugin idempotency.

### 4. Normal teardown

During pod deletion:

1. Runtime calls `NetworkTeardown` in reverse order.
2. Runtime destroys network namespace after teardown completes.

## Composability Model

These hooks are designed for multi-plugin pipelines.

### Shared state contract

`NetworkInterface` is the cross-plugin state object.

Plugins should:

- Preserve entries they do not own unless intentionally removing them.
- Append or update only owned data.
- Use `extension_attributes` for opaque plugin-private metadata needed by later chain stages.

### Ordering and ownership

Plugin order defines data flow and precedence.

A plugin later in the chain can consume and refine prior interface state. To keep behavior predictable, plugins should document ownership conventions for interface names, routes, and extension attributes.

## OCI LinuxNetDevice Integration

The core mapping for unprivileged handoff is:

- `host_interface_name`: host-side interface created by plugin.
- `container_interface_name`: desired in-pod name.

Runtimes can translate this mapping into OCI `LinuxNetDevice` entries and rely on low-level runtime operations to move/rename interfaces into the pod namespace.

This allows plugins to avoid privileged namespace entry patterns while still expressing exact interface intent.

## Plugin Implementation Guidance

### Recommended behavior

- Treat `NetworkSetup` as transactional relative to your plugin-owned resources.
- Make `NetworkTeardown` idempotent and safe to call repeatedly.
- Validate required pod annotations early and return actionable errors.
- Keep `NetworkCheck.reason` concise and operator-focused.

### Failure handling

- On setup error, return a clear reason that identifies the failed operation and resource.
- During teardown, tolerate missing resources and treat them as already-removed.

### Data hygiene

- Keep `extension_attributes` namespaced (for example, `example.com/key`) to avoid collisions across plugins.
- Avoid destructive rewrites of `current_interfaces` unless explicitly required.

## API Types

The network lifecycle messages are:

- `NetworkSetupRequest`
- `NetworkSetupResponse`
- `NetworkTeardownRequest`
- `NetworkTeardownResponse`
- `NetworkCheckRequest`
- `NetworkCheckResponse`
- `NetworkInterface`
- `Route`

See [pkg/api/api.proto](../pkg/api/api.proto) for canonical field definitions and comments.
