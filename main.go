package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
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

	firstRun := false

	var ingressProg, egressProg *ebpf.Program
	ingressPinPath := filepath.Join(ebpfFS, ingressProgName)
	egressPinPath := filepath.Join(ebpfFS, egressProgName)
	if firstRun {
		ingressProg = collec.Programs[ingressProgName]
		ingressProg.Pin(ingressPinPath)

		egressProg = collec.Programs[egressProgName]
		egressProg.Pin(egressPinPath)
	} else {
		ingressProg, err = ebpf.LoadPinnedProgram(ingressPinPath)
		if err != nil {
			fmt.Println(err)
			return
		}

		egressProg, err = ebpf.LoadPinnedProgram(egressPinPath)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	cgroup, err := os.Open(rootCgroup)
	if err != nil {
		return
	}
	defer cgroup.Close()

	if firstRun {
		_, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroup.Name(),
			Attach:  ebpf.AttachCGroupInetIngress,
			Program: collec.Programs[ingressProgName],
		})
		if err != nil {
			fmt.Println(err)
			return
		}

		_, err = link.AttachCgroup(link.CgroupOptions{
			Path:    cgroup.Name(),
			Attach:  ebpf.AttachCGroupInetEgress,
			Program: collec.Programs[egressProgName],
		})
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	var outputMap *ebpf.Map
	mapPinPath := filepath.Join(ebpfFS, flowMapName)
	if firstRun {
		outputMap, _ = collec.Maps[flowMapName]
		outputMap.Pin(mapPinPath)
	} else {
		outputMap, err = ebpf.LoadPinnedMap(mapPinPath)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	time.Sleep(3 * time.Second)
	var val record
	for outputMap.LookupAndDelete(nil, &val) == nil {
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

	if !firstRun {
		cgroup, err := os.Open(rootCgroup)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer cgroup.Close()

		ingressProg.Detach(int(cgroup.Fd()), ebpf.AttachCGroupInetIngress, 0)
		egressProg.Detach(int(cgroup.Fd()), ebpf.AttachCGroupInetEgress, 0)
	}
}
