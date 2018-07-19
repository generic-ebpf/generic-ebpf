BASE=	../../..
MACHINE!=	uname -m
MACHINE_ARCH!=	uname -p
include ${BASE}/Makefile.inc
ifeq (${MACHINE},"amd64")
JITSRC=	ebpf_jit_x86_64.c
endif
ifeq (${COVERAGE},"1")
CFLAGS+=	-coverage
LDFLAGS+=	-coverage
endif
include Makefile.common
