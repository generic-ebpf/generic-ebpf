.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../dev/ebpf

IDENT  != uname -i

CFLAGS += -I$(KSRC)/sys/$(MACHINE)/compile/$(IDENT)
CFLAGS += -I../../
CFLAGS += -Wall
CFLAGS += -std=c99

KMOD    = ebpf

CORES += ebpf_freebsd.c
CORES += ebpf_loader.c
CORES += ebpf_verifer.c
CORES += ebpf_vm.c
CORES += ebpf_prog.c
CORES += ebpf_allocator.c
CORES += ebpf_map.c

MAPS += ebpf_map_bad.c
MAPS += ebpf_map_array.c
MAPS += ebpf_map_hashtable.c

PROGS += ebpf_prog_bad.c

.if $(MACHINE) == "amd64"
CORES += ../../amd64/amd64/ebpf_jit_x86_64.c
.endif

SRCS += $(CORES)
SRCS += $(MAPS)
SRCS += $(PROGS)

realinstall:
	install ebpf.ko $(DESTDIR)

.include <bsd.kmod.mk>
