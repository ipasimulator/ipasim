#ifndef OBJC_PORT
// TODO: Define TARGET_CPU_X86, __MACH__ and then include this header, it should work!
#include "MacOSX10.13.sdk/usr/include/TargetConditionals.h"
#else
#define TARGET_CPU_X86 1

#define TARGET_OS_MAC 1
#define TARGET_OS_IPHONE 1
#define TARGET_OS_IOS 1

#define TARGET_RT_LITTLE_ENDIAN 1
#define TARGET_RT_MAC_MACHO 1
#endif
