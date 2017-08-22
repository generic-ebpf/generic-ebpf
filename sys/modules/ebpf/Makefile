.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../dev/ebpf

TARGET != uname -m
IDENT  != uname -i

CFLAGS += -I$(KSRC)/sys/$(TARGET)/compile/$(IDENT)
CFLAGS += -I../../

KMOD    = ebpf
SRCS    += ebpf_freebsd.c
SRCS    += ebpf_loader.c
SRCS    += ebpf_verifer.c
SRCS    += ebpf_vm.c

.if $(TARGET) == "amd64"
SRCS    += ../../amd64/amd64/ebpf_jit_x86_64.c
.endif

.include <bsd.kmod.mk>
