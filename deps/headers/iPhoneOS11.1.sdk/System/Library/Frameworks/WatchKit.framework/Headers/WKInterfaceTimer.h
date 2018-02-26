//
//  WKInterfaceTimer.h
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
@interface WKInterfaceTimer : WKInterfaceObject

- (void)setTextColor:(nullable UIColor *)color;

- (void)setDate:(NSDate *)date; // count up/down from current date to this date
- (void)start;
- (void)stop;

@end

NS_ASSUME_NONNULL_END
