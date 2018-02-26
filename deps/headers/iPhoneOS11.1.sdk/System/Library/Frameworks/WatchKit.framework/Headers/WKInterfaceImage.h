//
//  WKInterfaceImage.h
//  WatchKit
//
//  Copyright (c) 2014-2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>
#import <WatchKit/WKInterfaceObject.h>
#import <UIKit/UIColor.h>

NS_ASSUME_NONNULL_BEGIN

@class UIImage;

@protocol WKImageAnimatable <NSObject>

// Play all images repeatedly using duration specified in interface description.
- (void)startAnimating;

// Play a subset of images for a certain number of times. 0 means repeat until stop.
- (void)startAnimatingWithImagesInRange:(NSRange)imageRange duration:(NSTimeInterval)duration repeatCount:(NSInteger)repeatCount;

- (void)stopAnimating;

@end

WK_CLASS_AVAILABLE_IOS(8_2)
@interface WKInterfaceImage : WKInterfaceObject <WKImageAnimatable>

- (void)setImage:(nullable UIImage *)image;
- (void)setImageData:(nullable NSData *)imageData;
- (void)setImageNamed:(nullable NSString *)imageName;

- (void)setTintColor:(nullable UIColor *)tintColor;

@end

NS_ASSUME_NONNULL_END
