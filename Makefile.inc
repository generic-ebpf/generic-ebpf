CURDIR?=	$(PWD)
UNAME_s!=	uname -s
SHLIB_FreeBSD=	.so
SHLIB_Linux=	.so
SHLIB_Darwin=	.dylib
SHLIB=		$(SHLIB_$(UNAME_s))

KMODLOAD_FreeBSD=	kldload
KMODUNLOAD_FreeBSD=	kldunload
KMODLOAD_Linux=		insmod
KMODUNLOAD_Linux=	rmmod
KMODLOAD=	$(KMODLOAD_$(UNAME_s))
KMODUNLOAD=	$(KMODUNLOAD_$(UNAME_s))
SHLIB_VAL_FreeBSD=	LD_LIBRARY_PATH
SHLIB_VAL_Linux=	LD_LIBRARY_PATH
SHLIB_VAL_Darwin=	DYLD_LIBRARY_PATH
SHLIB_VAL= $(SHLIB_VAL_$(UNAME_s))

CC?=		cc
EBPFCC?=	clang

GTESTPATH?=	${BASE}/extern/googletest
GTESTMAIN?=	${GTESTPATH}/googletest/make/gtest_main.o
GTESTALL?=	${GTESTPATH}/googletest/make/gtest-all.o
GTESTOBJS?=	${GTESTMAIN} ${GTESTALL}

CKPATH?=	${BASE}/extern/ck-0.6.0
CKOBJS?=	${CKPATH}/src/libck.a

LIBEBPFDIR?=	${BASE}/${UNAME_s}/ebpf/user
LIBEBPF=	${LIBEBPFDIR}/libebpf${SHLIB}
EBPFKMODDIR?=	${BASE}/${UNAME_s}/ebpf/kernel
EBPFDEVKMODDIR?=${BASE}/${UNAME_s}/ebpf_dev
LIBGBPFDIR?=	${BASE}/contrib/libgbpf
LIBGBPF=	${LIBGBPFDIR}/libgbpf.a
TESTDIR=	${BASE}/tests
BENCHMARKDIR=	${BASE}/benchmark
VMISA_H=	${BASE}/sys/sys/ebpf_vm_isa.h
VMISA_I=	${BASE}/sys/dev/ebpf/ebpf_interpreter.c
VMISA_D=	${BASE}/sys/dev/ebpf/ebpf_disassembler.c

DEBUG_FLAGS=	-g

CXXFLAGS+=	${DEBUG_FLAGS} -Wall
CFLAGS+=	${DEBUG_FLAGS} -Wall

MAKE_CMD=	env ${MAKE_ENV} ${MAKE} ${.MAKEFLAGS} ${MAKE_ARGS}

all:
clean:
	rm -f ${CLEANFILES}
.PHONY:	all clean

${LIBEBPF}:
	cd $(LIBEBPFDIR) && ${MAKE_CMD} libebpf${SHLIB}
${LIBGBPF}:
	cd $(LIBGBPFDIR) && ${MAKE_CMD} libgbpf.a
${GTESTPATH}/googletest/make/gtest_main.o:
	cd $(GTESTPATH)/googletest/make && ${MAKE_CMD} gtest_main.o
${GTESTPATH}/googletest/make/gtest-all.o:
	cd $(GTESTPATH)/googletest/make && ${MAKE_CMD} gtest-all.o
${CKOBJS}:
	cd $(CKPATH) && ./configure && ${MAKE_CMD}
${VMISA_H}: ${BASE}/sys/dev/ebpf/ebpf_vm_isa.def ${BASE}/sys/dev/ebpf/ebpf_vm_isa.awk
	awk -v target="header" -f ${BASE}/sys/dev/ebpf/ebpf_vm_isa.awk ${BASE}/sys/dev/ebpf/ebpf_vm_isa.def > $@
${VMISA_I}: ${VMISA_H}
	awk -v target="interpreter" -f ${BASE}/sys/dev/ebpf/ebpf_vm_isa.awk ${BASE}/sys/dev/ebpf/ebpf_vm_isa.def > $@
${VMISA_D}: ${VMISA_H}
	awk -v target="disassembler" -f ${BASE}/sys/dev/ebpf/ebpf_vm_isa.awk ${BASE}/sys/dev/ebpf/ebpf_vm_isa.def > $@
CLEANFILES+=	${VMISA_H} ${VMISA_I_C} ${VMISA_D_C} ${VMISA_I_O} ${VMISA_D_O}
