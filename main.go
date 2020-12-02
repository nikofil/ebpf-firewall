package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

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
	flowMapName     = "flows"
	blockedMapName  = "blocked"
	bpfCodePath     = "bpf.o"
	egressProgName  = "egress"
	ingressProgName = "ingress"
)

func intToIP(val uint32) net.IP {
	return net.IPv4(byte(val&0xff), byte((val>>8)&0xff), byte((val>>16)&0xff), byte(val>>24))
}

func main() {
	if len(os.Args) == 1 {
		fmt.Println("Give an option: load, unload, show, block [address] or unblock [address]")
		return
	}

	unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})

	collec, err := ebpf.LoadCollection(bpfCodePath)
	if err != nil {
		fmt.Println(err)
		return
	}

	var ingressProg, egressProg *ebpf.Program
	ingressPinPath := filepath.Join(ebpfFS, ingressProgName)
	egressPinPath := filepath.Join(ebpfFS, egressProgName)

	cgroup, err := os.Open(rootCgroup)
	if err != nil {
		return
	}
	defer cgroup.Close()

	var outputMap *ebpf.Map
	mapPinPath := filepath.Join(ebpfFS, flowMapName)

	if os.Args[1] == "load" {
		ingressProg = collec.Programs[ingressProgName]
		ingressProg.Pin(ingressPinPath)

		egressProg = collec.Programs[egressProgName]
		egressProg.Pin(egressPinPath)

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

		outputMap, _ = collec.Maps[flowMapName]
		outputMap.Pin(mapPinPath)
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

		outputMap, err = ebpf.LoadPinnedMap(mapPinPath)
		if err != nil {
			fmt.Println(err)
			return
		}

		if os.Args[1] == "show" {
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
		} else if os.Args[1] == "unload" {
			cgroup, err := os.Open(rootCgroup)
			if err != nil {
				fmt.Println(err)
				return
			}
			defer cgroup.Close()

			ingressProg.Detach(int(cgroup.Fd()), ebpf.AttachCGroupInetIngress, 0)
			egressProg.Detach(int(cgroup.Fd()), ebpf.AttachCGroupInetEgress, 0)

			os.Remove(ingressPinPath)
			os.Remove(egressPinPath)
			os.Remove(mapPinPath)
		}
	}
}
