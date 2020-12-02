all:
	go get github.com/cilium/ebpf
	clang -O2 -emit-llvm -c bpf.c -o - | llc -march=bpf -filetype=obj -o bpf.o
	go build ./ebpf-fw.go

clean:
	rm -f ebpf-fw bpf.o
