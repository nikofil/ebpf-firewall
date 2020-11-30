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

type bpf struct {
	prog *ebpf.Program
}

const (
	rootCgroup     = "/sys/fs/cgroup/unified"
	mapName        = "lpm_filter"
	bpfCodePath    = "bpf.o"
	bpfProgramName = "egress"
)

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

	if _, ok := collec.Programs[bpfProgramName]; !ok {
		fmt.Println("Program not found:", bpfProgramName)
		return
	}
	firstRun := true
	cleanup := true
	var prog *ebpf.Program
	if firstRun {
		prog = collec.Programs[bpfProgramName]
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
	var val uint32
	for x.LookupAndDelete(nil, &val) == nil {
		if val == 0 {
			continue
		}
		ip := net.IPv4(byte(val&0xff), byte((val>>8)&0xff), byte((val>>16)&0xff), byte(val>>24))
		fmt.Println(ip)
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
