package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func main() {
	must(rlimit.RemoveMemlock())

	spec, err := ebpf.LoadCollectionSpec("drop_tcp_port_kern.o")
	must(err)

	coll, err := ebpf.NewCollection(spec)
	must(err)
	defer coll.Close()

	prog := coll.Programs["drop_tcp_port"]
	if prog == nil {
		log.Fatalf("Program 'drop_tcp_port' not found")
	}

	ifaceName := "wlp0s20f3"
	iface, err := net.InterfaceByName(ifaceName)
	must(err)

	// Clean up any existing link
	link.CloseAll()

	// Attach and replace existing XDP if needed
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // Change to XDPDriverMode if your NIC supports it
		Replace:   true,
	})
	must(err)
	defer lnk.Close()

	// Use port from CLI or default
	port := uint16(4040)
	if len(os.Args) > 1 {
		if p, err := strconv.Atoi(os.Args[1]); err == nil && p > 0 && p < 65535 {
			port = uint16(p)
		}
	}
	fmt.Printf("Blocking TCP port: %d\n", port)

	portMap := coll.Maps["blocked_port_map"]
	if portMap == nil {
		log.Fatalf("Map 'blocked_port_map' not found")
	}

	var key uint32 = 0
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, htons(port))

	err = portMap.Put(key, buf.Bytes())
	must(err)

	fmt.Println("XDP program attached. Press Ctrl+C to exit.")
	select {}
}
