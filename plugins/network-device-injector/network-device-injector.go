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
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"sigs.k8s.io/yaml"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"

	"github.com/Mellanox/rdmamap"
)

const (
	// Prefix of the key used for network device annotations.
	netdeviceKey = "netdevices.nri.io"
)

var (
	log     *logrus.Logger
	verbose bool
)

// an annotated netdevice
// https://man7.org/linux/man-pages/man7/netdevice.7.html
type netdevice struct {
	Name    string `json:"name"`     // name in the runtime namespace
	NewName string `json:"new_name"` // name inside the pod namespace
	Address string `json:"address"`
	Prefix  int32  `json:"prefix"`
	HWAddr  string `json:"hwaddr"`
	Flags   int32  `json:"flags"`
	Index   int32  `json:"index"`
	Metric  int32  `json:"metric"`
	MTU     int32  `json:"mtu"`
}

func (n *netdevice) inject(nsPath string) error {
	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	link, err := netlink.LinkByName(n.Name)
	if err != nil {
		return err
	}
	ns, err := netns.GetFromPath(nsPath)
	if err != nil {
		return err
	}
	defer ns.Close()
	// Devices can be renamed only when down
	err = netlink.LinkSetDown(link)
	if err != nil {
		return err
	}
	// Save host device name into the container device's alias property
	err = netlink.LinkSetAlias(link, link.Attrs().Name)
	if err != nil {
		return fmt.Errorf("fail to set alias for iface %s: %w", n.Name, err)
	}
	err = netlink.LinkSetNsFd(link, int(ns))
	if err != nil {
		return fmt.Errorf("fail to move link for iface %s to ns %d : %v", n.Name, int(ns), err)
	}
	// This is now inside the container namespace
	err = netns.Set(ns)
	if err != nil {
		return fmt.Errorf("fail to set to ns %d: %v", int(ns), err)
	}

	link, err = netlink.LinkByName(n.Name)
	if err != nil {
		return err
	}

	err = netlink.LinkSetName(link, n.NewName)
	if err != nil {
		return err
	}

	ip := net.ParseIP(n.Address)
	if ip == nil {
		return nil
	}

	// if no prefix
	if n.Prefix == 0 {
		if ip.To4() == nil {
			n.Prefix = 128
		} else {
			n.Prefix = 32
		}
	}

	nlAddr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", ip.String(), n.Prefix))
	if err != nil {
		log.Printf("error parsing address %s: %v", n.Address, err)
	}
	err = netlink.AddrAdd(link, nlAddr)
	if err != nil {
		log.Printf("error adding address %s: %v", n.Address, err)
	}

	return nil
}

// remove the network device from the Pod namespace and recover its name
// Leaves the interface in down state to avoid issues with the root network.
func (n *netdevice) release(nsPath string) error {
	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ns, err := netns.GetFromPath(nsPath)
	if err != nil {
		return err
	}
	defer ns.Close()

	// This is now inside the container namespace
	err = netns.Set(ns)
	if err != nil {
		return fmt.Errorf("fail to set to ns %d: %v", int(ns), err)
	}

	link, err := netlink.LinkByName(n.Name)
	if err != nil {
		return err
	}
	// Devices can be renamed only when down
	err = netlink.LinkSetDown(link)
	if err != nil {
		return err
	}

	err = netlink.LinkSetName(link, n.Name)
	if err != nil {
		return err
	}

	return nil
}

// an annotated device
type device struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Major    int64  `json:"major"`
	Minor    int64  `json:"minor"`
	FileMode uint32 `json:"file_mode"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
}

// our injector plugin
type plugin struct {
	stub stub.Stub
}

func (p *plugin) RunPodSandbox(_ context.Context, pod *api.PodSandbox) error {
	log.Infof("Started pod %s/%s...", pod.GetNamespace(), pod.GetName())
	if verbose {
		dump("RunPodSandbox", "pod", pod)
	}

	// inject associated devices of the netdevice to the container
	netdevices, err := parseNetdevices(pod.Annotations)
	if err != nil {
		return err
	}

	if len(netdevices) == 0 {
		return nil
	}

	// get the pod network namespace
	var ns string
	for _, namespace := range pod.Linux.GetNamespaces() {
		if namespace.Type == "network" {
			ns = namespace.Path
			break
		}
	}
	// TODO check host network namespace
	if ns == "" {
		return nil
	}

	// attach the network devices to the pod namespace
	for _, n := range netdevices {
		err = n.inject(ns)
		if err != nil {
			return nil
		}
	}
	return nil
}

func (p *plugin) StopPodSandbox(_ context.Context, pod *api.PodSandbox) error {
	log.Infof("Stopped pod %s/%s...", pod.GetNamespace(), pod.GetName())
	if verbose {
		dump("StopPodSandbox", "pod", pod)
	}
	// release associated devices of the netdevice to the Pod
	netdevices, err := parseNetdevices(pod.Annotations)
	if err != nil {
		return err
	}

	if len(netdevices) == 0 {
		return nil
	}

	// get the pod network namespace
	var ns string
	for _, namespace := range pod.Linux.GetNamespaces() {
		if namespace.Type == "network" {
			ns = namespace.Path
			break
		}
	}
	// TODO check host network namespace
	if ns == "" {
		return nil
	}

	// attach the network devices to the pod namespace
	for _, n := range netdevices {
		err = n.release(ns)
		if err != nil {
			return nil
		}
	}

	return nil
}

// CreateContainer handles container creation requests.
func (p *plugin) CreateContainer(_ context.Context, pod *api.PodSandbox, container *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	var (
		ctrName    string
		netdevices []netdevice
		devices    []device
		err        error
	)

	ctrName = containerName(pod, container)

	if verbose {
		dump("CreateContainer", "pod", pod, "container", container)
	}

	adjust := &api.ContainerAdjustment{}

	// inject associated devices of the netdevice to the container
	netdevices, err = parseNetdevices(pod.Annotations)
	if err != nil {
		return nil, nil, err
	}

	if len(netdevices) == 0 {
		log.Infof("%s: no devices annotated...", ctrName)
	} else {
		if verbose {
			dump(ctrName, "annotated devices", devices)
		}

		for _, n := range netdevices {
			rdmadev, err := rdmamap.GetRdmaDeviceForNetdevice(n.Name)
			if err != nil {
				log.Infof("%s: error trying to find the associated device %q : %v", ctrName, n.Name, err)
				continue
			}
			if rdmadev == "" {
				log.Infof("%s: no devices for net device %q...", ctrName, n.Name)
				continue
			}
			d := device{Path: rdmadev}

			adjust.AddDevice(d.toNRI())
			if !verbose {
				log.Infof("%s: injected device %q...", ctrName, d.Path)
			}
		}
	}

	if verbose {
		dump(ctrName, "ContainerAdjustment", adjust)
	}

	return adjust, nil, nil
}

func parseNetdevices(annotations map[string]string) ([]netdevice, error) {
	var (
		key        string
		annotation []byte
		netdevices []netdevice
	)

	// look up effective device annotation and unmarshal devices
	for _, key = range []string{
		netdeviceKey + "/pod",
		netdeviceKey,
	} {
		if value, ok := annotations[key]; ok {
			annotation = []byte(value)
			break
		}
	}

	if annotation == nil {
		return nil, nil
	}

	if err := yaml.Unmarshal(annotation, &netdevices); err != nil {
		return nil, fmt.Errorf("invalid device annotation %q: %w", key, err)
	}

	return netdevices, nil
}

// Convert a device to the NRI API representation.
func (d *device) toNRI() *api.LinuxDevice {
	apiDev := &api.LinuxDevice{
		Path:  d.Path,
		Type:  d.Type,
		Major: d.Major,
		Minor: d.Minor,
	}
	if d.FileMode != 0 {
		apiDev.FileMode = api.FileMode(d.FileMode)
	}
	if d.UID != 0 {
		apiDev.Uid = api.UInt32(d.UID)
	}
	if d.GID != 0 {
		apiDev.Gid = api.UInt32(d.GID)
	}
	return apiDev
}

// Construct a container name for log messages.
func containerName(pod *api.PodSandbox, container *api.Container) string {
	if pod != nil {
		return pod.Name + "/" + container.Name
	}
	return container.Name
}

// Dump one or more objects, with an optional global prefix and per-object tags.
func dump(args ...interface{}) {
	var (
		prefix string
		idx    int
	)

	if len(args)&0x1 == 1 {
		prefix = args[0].(string)
		idx++
	}

	for ; idx < len(args)-1; idx += 2 {
		tag, obj := args[idx], args[idx+1]
		msg, err := yaml.Marshal(obj)
		if err != nil {
			log.Infof("%s: %s: failed to dump object: %v", prefix, tag, err)
			continue
		}

		if prefix != "" {
			log.Infof("%s: %s:", prefix, tag)
			for _, line := range strings.Split(strings.TrimSpace(string(msg)), "\n") {
				log.Infof("%s:    %s", prefix, line)
			}
		} else {
			log.Infof("%s:", tag)
			for _, line := range strings.Split(strings.TrimSpace(string(msg)), "\n") {
				log.Infof("  %s", line)
			}
		}
	}
}

func main() {
	var (
		pluginName string
		pluginIdx  string
		opts       []stub.Option
		err        error
	)

	log = logrus.StandardLogger()
	log.SetFormatter(&logrus.TextFormatter{
		PadLevelText: true,
	})

	flag.StringVar(&pluginName, "name", "", "plugin name to register to NRI")
	flag.StringVar(&pluginIdx, "idx", "", "plugin index to register to NRI")
	flag.BoolVar(&verbose, "verbose", false, "enable (more) verbose logging")
	flag.Parse()

	if pluginName != "" {
		opts = append(opts, stub.WithPluginName(pluginName))
	}
	if pluginIdx != "" {
		opts = append(opts, stub.WithPluginIdx(pluginIdx))
	}

	p := &plugin{}
	if p.stub, err = stub.New(p, opts...); err != nil {
		log.Fatalf("failed to create plugin stub: %v", err)
	}

	err = p.stub.Run(context.Background())
	if err != nil {
		log.Errorf("plugin exited with error %v", err)
		os.Exit(1)
	}
}
