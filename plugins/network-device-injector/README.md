## Network Device Injector Plugin

This sample plugin can inject network devices and associated RDMA devices into containers using pod annotations.

### Network Device Annotations

Network devices are annotated using the `netdevices.nri.io` annotation key prefix.
Network devices are defined at the Pod level, since are part of the network namespace.

The annotation syntax for network device injection is

```
- name: enp2s2f0
  new_name: eth1
  address: 192.168.2.2
  netmask: 255.255.255.128
  mtu: 1500
- name: enp2s2f1
  ...
```

The parameters are based on the existing linux netdevice representation.
https://man7.org/linux/man-pages/man7/netdevice.7.html

`name` is mandatory and refers to the name of the network interface in the host,
the rest of the parameters is optional.
`new_name` is the name of the interface inside the Pod.

The plugin only injects interfaces on the Pod, for more advanced networking configuration
like routing, traffic redirection or dynamic address configuration new plugins can be created.

## Testing

You can test this plugin using a kubernetes cluster/node with a container
runtime that has NRI support enabled. Start the plugin on the target node
(`network-device-injector -idx 10`), create a pod with some annotated network devices or
mounts, then verify that those get injected to the containers according
to the annotations. See the [sample pod spec](sample-network-device-inject.yaml)
for an example.