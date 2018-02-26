//
//  UIFontMetrics.h
//  UIKit
//
//  Copyright (c) 2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UIKit/UIKitDefines.h>
#import <UIKit/UIFont.h>

NS_ASSUME_NONNULL_BEGIN

UIKIT_EXTERN API_AVAILABLE(ios(11.0),tvos(11.0),watchos(4.0))
@interface UIFontMetrics : NSObject

@property (class, readonly, strong) UIFontMetrics *defaultMetrics;

+ (instancetype)metricsForTextStyle:(UIFontTextStyle)textStyle;

- (instancetype)init NS_UNAVAILABLE;
- (instancetype)initForTextStyle:(UIFontTextStyle)textStyle NS_DESIGNATED_INITIALIZER;

- (UIFont *)scaledFontForFont:(UIFont *)font;
- (UIFont *)scaledFontForFont:(UIFont *)font maximumPointSize:(CGFloat)maximumPointSize;
- (UIFont *)scaledFontForFont:(UIFont *)font compatibleWithTraitCollection:(nullable UITraitCollection *)traitCollection __WATCHOS_PROHIBITED;
- (UIFont *)scaledFontForFont:(UIFont *)font maximumPointSize:(CGFloat)maximumPointSize compatibleWithTraitCollection:(nullable UITraitCollection *)traitCollection __WATCHOS_PROHIBITED;

- (CGFloat)scaledValueForValue:(CGFloat)value;
- (CGFloat)scaledValueForValue:(CGFloat)value compatibleWithTraitCollection:(nullable UITraitCollection *)traitCollection __WATCHOS_PROHIBITED;

@end

NS_ASSUME_NONNULL_END
