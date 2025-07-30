BPF_CLANG=clang
CFLAGS=-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86

all: drop_tcp_port_kern.o

drop_tcp_port_kern.o: bpf/drop_tcp_port_kern.c
	$(BPF_CLANG) $(CFLAGS) -c bpf/drop_tcp_port_kern.c -o drop_tcp_port_kern.o

clean:
	rm -f *.o
