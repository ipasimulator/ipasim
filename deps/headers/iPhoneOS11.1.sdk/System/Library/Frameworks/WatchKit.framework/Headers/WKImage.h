//
//  WKImage.h
//  WatchKit
//
//  Copyright (c) 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class UIImage;

WK_AVAILABLE_WATCHOS_ONLY(2.0)
@interface WKImage : NSObject <NSCopying, NSSecureCoding>

+ (instancetype)imageWithImage:(UIImage *)image;
+ (instancetype)imageWithImageData:(NSData *)imageData;
+ (instancetype)imageWithImageName:(NSString *)imageName;

- (instancetype)init NS_UNAVAILABLE;

@property (readonly, nullable) UIImage *image;
@property (readonly, nullable) NSData *imageData;
@property (readonly, nullable) NSString *imageName;

@end

NS_ASSUME_NONNULL_END
