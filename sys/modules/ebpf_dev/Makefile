.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../dev/ebpf_dev

TARGET != uname -m
IDENT  != uname -i

CFLAGS += -I$(KSRC)/sys/$(TARGET)/compile/$(IDENT)
CFLAGS += -I../../

KMOD    = ebpf-dev

SRCS += ebpf_dev_freebsd.c
SRCS += ebpf_obj.c
SRCS += ebpf_dev.c

.include <bsd.kmod.mk>
