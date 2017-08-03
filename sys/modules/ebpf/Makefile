.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../dev/ebpf

TARGET! = uname -m
IDENT!  = uname -i

CFLAGS += -I$(KSRC)/sys/$(TARGET)/compile/$(IDENT)
CFLAGS += -I../../

KMOD    = ebpf
SRCS    += ebpf_int.h
SRCS    += ebpf_freebsd.c
SRCS    += ebpf_loader.c
SRCS    += ebpf_vm.c

.include <bsd.kmod.mk>
