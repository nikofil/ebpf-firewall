package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type record struct {
	Flags uint32
	Dstip uint32
	Srcip uint32
}

const (
	rootCgroup      = "/sys/fs/cgroup/unified"
	ebpfFS          = "/sys/fs/bpf"
	flowMapName     = "my_map"
	bpfCodePath     = "bpf.o"
	egressProgName  = "egress"
	ingressProgName = "ingress"
)

func intToIP(val uint32) net.IP {
	return net.IPv4(byte(val&0xff), byte((val>>8)&0xff), byte((val>>16)&0xff), byte(val>>24))
}

func main() {
	unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})

	collec, err := ebpf.LoadCollection(bpfCodePath)
	if err != nil {
		fmt.Println(err)
		return
	}

	if _, ok := collec.Programs[egressProgName]; !ok {
		fmt.Println("Program not found:", egressProgName)
		return
	}
	firstRun := true
	cleanup := true
	var prog *ebpf.Program
	if firstRun {
		prog = collec.Programs[egressProgName]
		prog.Pin("/sys/fs/bpf/myprog")
	} else {
		prog, _ = ebpf.LoadPinnedProgram("/sys/fs/bpf/myprog")
	}

	cgroup, err := os.Open(rootCgroup)
	if err != nil {
		return
	}
	defer cgroup.Close()

	if firstRun {
		_, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroup.Name(),
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: collec.Programs["egress"],
		})
		if err != nil {
			return
		}
	}

	var x *ebpf.Map
	var e error
	var ok bool
	if firstRun {
		x, ok = collec.Maps["my_map"]
		x.Pin("/sys/fs/bpf/my_map1")
		fmt.Println(ok)
	} else {
		x, e = ebpf.LoadPinnedMap("/sys/fs/bpf/my_map1")
		fmt.Println(e)
	}
	time.Sleep(3 * time.Second)
	var val record
	for x.LookupAndDelete(nil, &val) == nil {
		if val.Dstip == 0 {
			continue
		}
		dstip := intToIP(val.Dstip)
		srcip := intToIP(val.Srcip)
		egress := (val.Flags & 1) != 0
		blocked := (val.Flags & 2) != 0

		var pktFlow string
		if egress {
			pktFlow = fmt.Sprintf("%v -> %v", srcip, dstip)
		} else {
			pktFlow = fmt.Sprintf("%v <- %v", dstip, srcip)
		}
		if blocked {
			pktFlow += " [BLOCKED]"
		}
		fmt.Println(pktFlow)
	}

	if cleanup {
		if prog != nil {
			cgroup, err := os.Open(rootCgroup)
			if err != nil {
				return
			}
			defer cgroup.Close()

			prog.Detach(int(cgroup.Fd()), ebpf.AttachCGroupInetEgress, 0)
		}
	}
}
