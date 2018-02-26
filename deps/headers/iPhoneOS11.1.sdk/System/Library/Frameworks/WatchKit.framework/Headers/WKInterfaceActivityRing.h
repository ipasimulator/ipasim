//
//  WKInterfaceActivityRing.h
//  WatchKit
//
//  Copyright (c) 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>
#import <WatchKit/WKInterfaceObject.h>

@class HKActivitySummary;

NS_ASSUME_NONNULL_BEGIN

WK_AVAILABLE_WATCHOS_ONLY(2.2)
@interface WKInterfaceActivityRing : WKInterfaceObject

- (void)setActivitySummary:(nullable  HKActivitySummary *)activitySummary animated:(BOOL)animated;

@end

NS_ASSUME_NONNULL_END
