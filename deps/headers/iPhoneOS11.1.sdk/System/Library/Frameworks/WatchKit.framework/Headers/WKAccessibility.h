//
//  WKAccessibility.h
//  WatchKit
//
//  Copyright (c) 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>

NS_ASSUME_NONNULL_BEGIN

WKI_EXTERN BOOL WKAccessibilityIsVoiceOverRunning() WK_AVAILABLE_WATCHOS_ONLY(2.0);
WKI_EXTERN NSString *const WKAccessibilityVoiceOverStatusChanged WK_AVAILABLE_WATCHOS_ONLY(2.0);

WKI_EXTERN BOOL WKAccessibilityIsReduceMotionEnabled() WK_AVAILABLE_WATCHOS_ONLY(4.0);
WKI_EXTERN NSString *const WKAccessibilityReduceMotionStatusDidChangeNotification WK_AVAILABLE_WATCHOS_ONLY(4.0);

NS_ASSUME_NONNULL_END
