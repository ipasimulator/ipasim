//
//  WKInterfaceSwitch.h
//  WatchKit
//
//  Copyright (c) 2014-2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>
#import <WatchKit/WKInterfaceObject.h>
#import <UIKit/UIColor.h>

NS_ASSUME_NONNULL_BEGIN

WK_CLASS_AVAILABLE_IOS(8_2)
@interface WKInterfaceSwitch : WKInterfaceObject

- (void)setTitle:(nullable NSString *)title;
- (void)setAttributedTitle:(nullable NSAttributedString *)attributedTitle;

- (void)setEnabled:(BOOL)enabled;
- (void)setOn:(BOOL)on;
- (void)setColor:(nullable UIColor *)color;

@end

NS_ASSUME_NONNULL_END
