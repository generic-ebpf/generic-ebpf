# generic-ebpf
Generic eBPF VM. Currently support FreeBSD kernel, FreeBSD userspace, Linux kernel and Linux userspace.

# Installation

### Kernel Space

#### FreeBSD

```
$ cd generic-ebpf/FreeBSD/kernel
$ make
# kldload ./ebpf.ko
```

### Linux

```
$ cd generic-ebpf/LINUX/kernel
$ make
# insmod ebpf.ko
```

### User Space

#### FreeBSD

```
$ cd generic-ebpf/FreeBSD/user
$ make
```

After compilation, you see libebpf.a. Please statically link it to your program.
#### Linux

```
$ cd generic-ebpf/Linux/user
$ make
```

After compilation, you see libebpf.a. Please statically link it to your program.

## Example Applications

### [VALE-BPF](https://github.com/YutaroHayakawa/vale-bpf)

Enhansing eBPF programmability to [VALE](http://info.iet.unipi.it/~luigi/papers/20121026-vale.pdf)
(a.k.a. [mSwitch](https://pdfs.semanticscholar.org/ec44/8ceb3e05b9222113366dace9fdd2a62322de.pdf))
 a very fast and modular software switch.
