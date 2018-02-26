//
//  WKAlertAction.h
//  WatchKit
//
//  Copyright (c) 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, WKAlertActionStyle) {
    WKAlertActionStyleDefault = 0,
    WKAlertActionStyleCancel,
    WKAlertActionStyleDestructive
} WK_AVAILABLE_WATCHOS_ONLY(2.0);

typedef void (^WKAlertActionHandler)(void) WK_AVAILABLE_WATCHOS_ONLY(2.0);

WK_AVAILABLE_WATCHOS_ONLY(2.0)
@interface WKAlertAction : NSObject

+ (instancetype)actionWithTitle:(NSString *)title style:(WKAlertActionStyle)style handler:(WKAlertActionHandler)handler;

- (instancetype)init NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
