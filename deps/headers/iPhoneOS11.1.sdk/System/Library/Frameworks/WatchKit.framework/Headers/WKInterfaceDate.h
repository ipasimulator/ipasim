//
//  WKInterfaceDate.h
//  WatchKit
//
//  Copyright (c) 2014-2015 Apple Inc. All rights reserved.
//

#import <WatchKit/WatchKit.h>
#import <WatchKit/WKDefines.h>
#import <WatchKit/WKInterfaceObject.h>

NS_ASSUME_NONNULL_BEGIN

@class UIColor;

WK_CLASS_AVAILABLE_IOS(8_2)
@interface WKInterfaceDate : WKInterfaceObject

- (void)setTextColor:(nullable UIColor *)color;

- (void)setTimeZone:(nullable NSTimeZone *)timeZone;
- (void)setCalendar:(nullable NSCalendar *)calendar;

@end

NS_ASSUME_NONNULL_END
