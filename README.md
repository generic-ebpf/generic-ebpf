# generic-ebpf
Generic eBPF runtime. It (currently) consists of two components

1. ebpf: Portable interpreter, JIT compiler, and ebpf subsystems (e.g. map) library, works in both of userspace and kernel.
2. ebpf_dev: Character device for loading ebpf program or other related objects (e.g. map) into kernel. Alternative of Linux bpf(2).

Current support status

|               |ebpf               |ebpf_dev           |
|:--------------|:------------------|:------------------|
|FreeBSD Kernel |Yes                |Yes                |
|FreeBSD User   |Yes                |-                  |
|Linux Kernel   |Yes                |Yes                |
|Linux User     |Yes                |-                  |
|MacOSX User    |Currently broken   |-                  |

# Installation

```
// Pull submoduled googletest and compile ck
$ make init
// Install Python packages
$ pip install -r requirements.txt
```

```
$ make
$ cd tests && make
```

After compilation, you will see at least one of below
- ebpf.ko: Kernel module for ebpf library
- ebpf-dev.ko: Kernel module for ebpf_dev character device
- libebpf.so: User space library for ebpf

Please load or link them. Note that ebpf_dev.ko depends on ebpf.ko, so please load ebpf.ko before ebpf_dev.ko

## Running tests

### Tests for user space library
```
// After make
$ make check
```

### Tests for kernel
```
// After make
# make load
# make check-kern
```

## Example Applications

### [VALE-BPF](https://github.com/YutaroHayakawa/vale-bpf)

Enhansing eBPF programmability to [VALE](http://info.iet.unipi.it/~luigi/papers/20121026-vale.pdf)
(a.k.a. [mSwitch](https://pdfs.semanticscholar.org/ec44/8ceb3e05b9222113366dace9fdd2a62322de.pdf))
 a very fast and modular software switch.
 
## Notes
Our ebpf interpreter and jit codes (and its tests) are based on [ubpf](https://github.com/iovisor/ubpf)

## Dependency

- BSD style libelf
- Concurrency Kit
- Google Test
