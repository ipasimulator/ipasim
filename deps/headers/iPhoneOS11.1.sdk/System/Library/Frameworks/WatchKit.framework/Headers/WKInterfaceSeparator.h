//
//  WKInterfaceSeparator.h
//  WatchKit
//
//  Copyright (c) 2014-2015 Apple Inc. All rights reserved.
//

#import <WatchKit/WKDefines.h>
#import <WatchKit/WKInterfaceObject.h>

NS_ASSUME_NONNULL_BEGIN

@class UIColor;

WK_CLASS_AVAILABLE_IOS(8_2)
@interface WKInterfaceSeparator : WKInterfaceObject

- (void)setColor:(nullable UIColor *)color;

@end

NS_ASSUME_NONNULL_END
