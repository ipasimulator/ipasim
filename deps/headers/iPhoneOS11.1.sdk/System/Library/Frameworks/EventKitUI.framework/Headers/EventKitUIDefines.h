/*
 *  EventKitUIDefines.h
 *  EventKitUI
 *
 *  Copyright 2010 Apple Inc. All rights reserved.
 *
 */

#ifdef __cplusplus
#define EVENTKITUI_EXTERN               extern "C" __attribute__((visibility ("default")))
#else
#define EVENTKITUI_EXTERN               extern __attribute__((visibility ("default")))
#endif

#define EVENTKITUI_CLASS_AVAILABLE(_iphoneIntro) __attribute__((visibility("default"))) NS_CLASS_AVAILABLE(NA, _iphoneIntro)

#ifndef EKUI_HAS_HEADER
#define EKUI_HAS_HEADER(include_path) (defined(__has_include) && __has_include(include_path))
#endif

#ifndef EKUI_IS_IOS
#define EKUI_IS_IOS (defined(TARGET_OS_IOS) && TARGET_OS_IOS)
#endif

#ifndef EKUI_IS_SIMULATOR
#define EKUI_IS_SIMULATOR (defined(TARGET_OS_SIMULATOR) && TARGET_OS_SIMULATOR)
#endif
