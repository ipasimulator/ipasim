//
//  WKInterfaceSlider.h
//  WatchKit
//
//  Copyright (c) 2014-2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>
#import <WatchKit/WKInterfaceObject.h>

NS_ASSUME_NONNULL_BEGIN

@class UIColor;

WK_CLASS_AVAILABLE_IOS(8_2)
@interface WKInterfaceSlider : WKInterfaceObject

- (void)setEnabled:(BOOL)enabled;
- (void)setValue:(float)value;
- (void)setColor:(nullable UIColor *)color;
- (void)setNumberOfSteps:(NSInteger)numberOfSteps;

@end

NS_ASSUME_NONNULL_END
