package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "log"
    "os"
    "strconv"
	"net"
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
    // Allow the current process to lock memory for BPF maps
    must(rlimit.RemoveMemlock())

    // Load compiled program from ELF
    spec, err := ebpf.LoadCollectionSpec("drop_tcp_port_kern.o")
    must(err)

    coll, err := ebpf.NewCollection(spec)
    must(err)
    defer coll.Close()

    prog := coll.Programs["drop_tcp_port"]
    if prog == nil {
        log.Fatalf("Program 'drop_tcp_port' not found")
    }

    iface := "wlp0s20f3" // adjust if needed
    lnk, err := link.AttachXDP(link.XDPOptions{
        Program:   prog,
        Interface: ifaceIndex(iface),
        Flags:     link.XDPGenericMode,
    })
    must(err)
    defer lnk.Close()

    // Set the blocked port
    port := uint16(4040)
    if len(os.Args) > 1 {
        p, err := strconv.Atoi(os.Args[1])
        if err == nil && p > 0 && p < 65535 {
            port = uint16(p)
        }
    }

    fmt.Printf("Blocking TCP port: %d\n", port)

    portMap := coll.Maps["blocked_port_map"]
    if portMap == nil {
        log.Fatalf("Map 'blocked_port_map' not found")
    }

    var key uint32 = 0
    value := new(bytes.Buffer)
    binary.Write(value, binary.BigEndian, port)

    err = portMap.Put(key, value.Bytes())
    must(err)

    fmt.Println("eBPF XDP program attached. Press Ctrl+C to stop.")
    select {}
}

// Convert interface name to index
func ifaceIndex(name string) int {
    iface, err := net.InterfaceByName(name)
    must(err)
    return iface.Index
}
