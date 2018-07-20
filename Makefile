BASE=	.
.include "${BASE}/Makefile.inc"
.include "Makefile.common"
.if defined(SUBDIR) && !empty(SUBDIR)
clean: afterclean
afterclean:
	for D in ${SUBDIR}; do (cd $$D && make clean); done
.PHONY: afterclean
.endif

reload:
	-kldunload ebpf
	-kldunload ebpf-dev
	kldload ./ebpf.ko
	kldload ./ebpf-dev.ko

debug:
	sudo debug/debug
