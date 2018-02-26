//
//  PHContentEditingOutput.h
//  Photos
//
//  Copyright (c) 2014 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Photos/PhotosDefines.h>

@class PHContentEditingInput, PHAdjustmentData;

NS_ASSUME_NONNULL_BEGIN

PHOTOS_CLASS_AVAILABLE_IOS_TVOS(8_0, 10_0) @interface PHContentEditingOutput : NSObject

- (instancetype)initWithContentEditingInput:(PHContentEditingInput *)contentEditingInput;

@property (readwrite, strong, nullable) PHAdjustmentData *adjustmentData;

// File URL where the rendered output, with adjustments baked-in, needs to be written to.
@property (readonly, copy) NSURL *renderedContentURL;

@end

NS_ASSUME_NONNULL_END
