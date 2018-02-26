//
//  WKInterfaceGroup.h
//  WatchKit
//
//  Copyright (c) 2014-2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>
#import <WatchKit/WKInterfaceObject.h>
#import <WatchKit/WKInterfaceImage.h>
#import <UIKit/UIGeometry.h>

NS_ASSUME_NONNULL_BEGIN

@class UIColor, UIImage;
@protocol WKImageAnimatable;

WK_CLASS_AVAILABLE_IOS(8_2)
@interface WKInterfaceGroup : WKInterfaceObject <WKImageAnimatable>

- (void)setCornerRadius:(CGFloat)cornerRadius;
- (void)setContentInset:(UIEdgeInsets)contentInset WK_AVAILABLE_WATCHOS_ONLY(2.0);

- (void)setBackgroundColor:(nullable UIColor *)color;
- (void)setBackgroundImage:(nullable UIImage *)image;
- (void)setBackgroundImageData:(nullable NSData *)imageData;
- (void)setBackgroundImageNamed:(nullable NSString *)imageName;

@end

NS_ASSUME_NONNULL_END
