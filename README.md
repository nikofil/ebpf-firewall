# ebpf-fw

A very simple firewall, harnessing the power of eBPFs! The eBPF is attached to the root cgroup and is used to control whether packets are allowed through.

Requires Linux >= 4.10 (ie. CentOS 8 or Ubuntu 17.04).

Great eBPF reference: <https://docs.cilium.io/en/v1.9/bpf/>


## Requirements

Building requires the following on CentOS 8:
`yum install -y clang llvm go`  
or on Ubuntu:
`apt install -y clang llvm golang make`

cgroup2 FS must be mounted. By default it looks for it on `/sys/fs/cgroup/unified` but if it's not mounted there you can do:
```
sudo mkdir /mnt/cgroup2
sudo mount -t cgroup2 none /mnt/cgroup2
```
and change the path to `/mnt/cgroup2` in `ebpf-fw.go`


## Building

`make`


## Running

All must run as root.

Load eBPF with:  
`./ebpf-fw load`

Show tracked connections with:  
`./ebpf-fw show`

Block an IP with:  
`./ebpf-fw block 1.2.3.4`

Unblock an IP with:  
`./ebpf-fw unblock 1.2.3.4`

Unload eBPF with:  
`./ebpf-fw unload`
