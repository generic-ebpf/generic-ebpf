.CURDIR?=	$(PWD)
UNAME_s!=	uname -s
GTESTPATH?=	${BASE}/extern/googletest
GTESTOBJS?=	${GTESTPATH}/googletest/make/gtest_main.o \
		${GTESTPATH}/googletest/make/gtest-all.o

LIBEBPFDIR?=	${BASE}/${UNAME_s}/ebpf/user
EBPFKMODDIR?=	${BASE}/${UNAME_s}/ebpf/kernel
EBPFDEVKMODDIR?=${BASE}/${UNAME_s}/ebpf_dev
LIBGBPFDIR?=	${BASE}/tools/libgbpf

CXXFLAGS+=	-g
CFLAGS+=	-g

MAKE_CMD=	env ${MAKE_ENV} ${MAKE} ${.MAKEFLAGS} ${MAKE_ARGS}

all:
clean:
	rm -f ${CLEANFILES}

${GTESTPATH}/googletest/make/gtest_main.o:
	cd $(GTESTPATH)/googletest/make && ${MAKE_CMD} gtest_main.o
${GTESTPATH}/googletest/make/gtest-all.o:
	cd $(GTESTPATH)/googletest/make && ${MAKE_CMD} gtest-all.o
