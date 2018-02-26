//
//  PhotosDefines.h
//  PhotoKit
//
//  Copyright © 2016 Apple Inc. All rights reserved.
//

#import <Availability.h>

#ifdef __cplusplus
#define PHOTOS_EXTERN            extern "C" __attribute__((visibility ("default")))
#else
#define PHOTOS_EXTERN	        extern __attribute__((visibility ("default")))
#endif

#define PHOTOS_STATIC_INLINE	static inline

#define PHOTOS_AVAILABLE_IOS_ONLY(vers)                 __IOS_AVAILABLE(vers) __WATCHOS_UNAVAILABLE __TVOS_UNAVAILABLE
#define PHOTOS_AVAILABLE_WATCHOS_ONLY(vers)             __IOS_UNAVAILABLE __WATCHOS_AVAILABLE(vers) __TVOS_UNAVAILABLE
#define PHOTOS_AVAILABLE_TVOS_ONLY(vers)                __IOS_UNAVAILABLE __WATCHOS_UNAVAILABLE __TVOS_AVAILABLE(vers)
#define PHOTOS_AVAILABLE_IOS_TVOS(_ios, _tvos)          __IOS_AVAILABLE(_ios) __TVOS_AVAILABLE(_tvos)
#define PHOTOS_AVAILABLE_IOS_TVOS_OSX(_ios, _tvos, _osx)            __IOS_AVAILABLE(_ios) __TVOS_AVAILABLE(_tvos) __OSX_AVAILABLE(_osx)
#define PHOTOS_AVAILABLE_IOS_WATCHOS_TVOS(_ios, _watchos, _tvos)    __IOS_AVAILABLE(_ios) __WATCHOS_AVAILABLE(_watchos) __TVOS_AVAILABLE(_tvos)

#define PHOTOS_CLASS_AVAILABLE_IOS_ONLY(vers)           PHOTOS_EXTERN __IOS_AVAILABLE(vers) __WATCHOS_UNAVAILABLE __TVOS_UNAVAILABLE
#define PHOTOS_CLASS_AVAILABLE_WATCHOS_ONLY(vers)       PHOTOS_EXTERN __IOS_UNAVAILABLE __WATCHOS_AVAILABLE(vers) __TVOS_UNAVAILABLE
#define PHOTOS_CLASS_AVAILABLE_TVOS_ONLY(vers)          PHOTOS_EXTERN __IOS_UNAVAILABLE __WATCHOS_UNAVAILABLE __TVOS_AVAILABLE(vers)
#define PHOTOS_CLASS_AVAILABLE_IOS_TVOS(_ios, _tvos)    PHOTOS_EXTERN __IOS_AVAILABLE(_ios) __TVOS_AVAILABLE(_tvos)
#define PHOTOS_CLASS_AVAILABLE_IOS_TVOS_OSX(_ios, _tvos, _osx)          PHOTOS_EXTERN __IOS_AVAILABLE(_ios) __TVOS_AVAILABLE(_tvos) __OSX_AVAILABLE(_osx)
#define PHOTOS_CLASS_AVAILABLE_IOS_WATCHOS_TVOS(_ios, _watchos, _tvos)  PHOTOS_EXTERN __IOS_AVAILABLE(_ios) __WATCHOS_AVAILABLE(_watchos) __TVOS_AVAILABLE(_tvos)

#define PHOTOS_ENUM_AVAILABLE_IOS_ONLY(vers)            PHOTOS_AVAILABLE_IOS_ONLY(vers)
#define PHOTOS_ENUM_AVAILABLE_WATCHOS_ONLY(vers)        PHOTOS_AVAILABLE_WATCHOS_ONLY(vers)
#define PHOTOS_ENUM_AVAILABLE_TVOS_ONLY(vers)           PHOTOS_AVAILABLE_TVOS_ONLY(vers)
#define PHOTOS_ENUM_AVAILABLE_IOS_TVOS(_ios, _tvos)     PHOTOS_AVAILABLE_IOS_TVOS(_ios, _tvos)
#define PHOTOS_ENUM_AVAILABLE_IOS_TVOS_OSX(_ios, _tvos, _osx)          PHOTOS_AVAILABLE_IOS_TVOS_OSX(_ios, _tvos, _osx)
#define PHOTOS_ENUM_AVAILABLE_IOS_WATCHOS_TVOS(_ios, _watchos, _tvos)  PHOTOS_AVAILABLE_IOS_WATCHOS_TVOS(_ios, _watchos, _tvos)
