# ebpf-port-blocker

A minimal eBPF/XDP-based utility written in Go and C to **drop TCP packets** on a specific port (default: `4040`). Includes optional support to configure the port dynamically from user space.

---

## 🔧 Features

- Drops incoming TCP packets on a specified port (default: 4040)
- Lightweight and fast using XDP (eXpress Data Path)
- Optional: Set port dynamically from user space using BPF maps
- Written using eBPF and Go with `cilium/ebpf` or `libbpf` depending on approach

---

## 🚀 Getting Started

### Prerequisites

- A Linux system with:
  - Kernel ≥ 5.8 (recommended)
  - `clang` and `llvm` for compiling eBPF code
  - Root access
- Go 1.18+
- `bpftool` (for debugging/inspection)
- [libbpf](https://github.com/libbpf/libbpf) or [cilium/ebpf](https://github.com/cilium/ebpf) (Go)

---

### 🛠️ Build & Run (Example)

```bash
# Clone the repo
git clone https://github.com/Prakhar-Shankar/ebpf-port-blocker.git
cd ebpf-port-blocker

# Build Go binary (if applicable)
go build -o port-blocker

# Run with sudo (default port 4040)
sudo ./port-blocker
