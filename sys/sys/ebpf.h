#pragma once

#if defined(__FreeBSD__)
  #if defined(_KERNEL)
    #include "ebpf_freebsd_types.h"
  #else
    #include "ebpf_freebsd_user_types.h"
  #endif
#elif defined(linux)
  #if defined(_KERNEL)
    #include "ebpf_linux_types.h"
  #else
    #include "ebpf_linux_user_types.h"
  #endif
#elif defined(__Apple__)
  #if defined(_KERNEL)
    #error Unsupported platform
  #else
    #include "ebpf_darwin_types.h"
  #endif
#else
  #error Unsupported platform
#endif

#define EBPF_PSEUDO_MAP_DESC 1
#define EBPF_PROG_MAX_ATTACHED_MAPS 64
