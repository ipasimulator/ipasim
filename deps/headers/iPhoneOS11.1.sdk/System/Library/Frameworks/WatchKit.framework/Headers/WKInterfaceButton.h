//
//  WKInterfaceButton.h
//  WatchKit
//
//  Copyright (c) 2014-2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>
#import <WatchKit/WKInterfaceObject.h>

NS_ASSUME_NONNULL_BEGIN

@class UIImage, UIColor;

WK_CLASS_AVAILABLE_IOS(8_2)
@interface WKInterfaceButton : WKInterfaceObject

- (void)setTitle:(nullable NSString *)title;
- (void)setAttributedTitle:(nullable NSAttributedString *)attributedTitle;

- (void)setBackgroundColor:(nullable UIColor *)color;
- (void)setBackgroundImage:(nullable UIImage *)image;
- (void)setBackgroundImageData:(nullable NSData *)imageData;
- (void)setBackgroundImageNamed:(nullable NSString *)imageName;

- (void)setEnabled:(BOOL)enabled;

@end

NS_ASSUME_NONNULL_END
