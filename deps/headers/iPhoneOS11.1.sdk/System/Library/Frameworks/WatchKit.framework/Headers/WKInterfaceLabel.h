//
//  WKInterfaceLabel.h
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
@interface WKInterfaceLabel : WKInterfaceObject

- (void)setText:(nullable NSString *)text;
- (void)setTextColor:(nullable UIColor *)color;

- (void)setAttributedText:(nullable NSAttributedString *)attributedText;

@end

NS_ASSUME_NONNULL_END
