.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../dev/ebpf

TARGET != uname -m
IDENT  != uname -i

CFLAGS += -I$(KSRC)/sys/$(TARGET)/compile/$(IDENT)
CFLAGS += -I../../

KMOD    = ebpf

CORES += ebpf_freebsd.c
CORES += ebpf_loader.c
CORES += ebpf_verifer.c
CORES += ebpf_vm.c
CORES += ebpf_prog.c
CORES += ebpf_map.c

MAPS += ebpf_map_array.c

.if $(TARGET) == "amd64"
CORES += ../../amd64/amd64/ebpf_jit_x86_64.c
.endif

SRCS += $(CORES)
SRCS += $(MAPS)

.include <bsd.kmod.mk>
