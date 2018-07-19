BASE=	../../..
.include "${BASE}/Makefile.inc"
.include <bsd.own.mk>
.if ${MACHINE} == "amd64"
JITSRC=	ebpf_jit_x86_64.c
.endif
.if defined(COVERAGE) && !empty(COVERAGE)
CFLAGS+=	-coverage
LDFLAGS+=	-coverage
.endif
.include "Makefile.common"
