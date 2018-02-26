//
//  PHLivePhoto.h
//  PhotoKit
//
//  Copyright © 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <Photos/PhotosDefines.h>

#import "PhotosTypes.h"

NS_ASSUME_NONNULL_BEGIN

typedef int32_t PHLivePhotoRequestID PHOTOS_AVAILABLE_IOS_TVOS(9_1, 10_0);
static const PHLivePhotoRequestID PHLivePhotoRequestIDInvalid = 0;

/// These keys may be found in the info dictionary delivered to a live photo request result handler block.
extern NSString * const PHLivePhotoInfoErrorKey PHOTOS_AVAILABLE_IOS_TVOS(9_1, 10_0); // key : NSError decribing an error that has occurred while creating the live photo
extern NSString * const PHLivePhotoInfoIsDegradedKey PHOTOS_AVAILABLE_IOS_TVOS(9_1, 10_0); // key : NSNumber containing a BOOL, YES whenever the deivered live photo object does not contain all content required for full playback.
extern NSString * const PHLivePhotoInfoCancelledKey PHOTOS_AVAILABLE_IOS_TVOS(9_1, 10_0); // key : NSNumber containing a BOOL, YES when the result handler is being called after the request has been cancelled.


PHOTOS_CLASS_AVAILABLE_IOS_TVOS(9_1, 10_0)
@interface PHLivePhoto : NSObject <NSCopying, NSSecureCoding>

/// The dimensions of the live photo measured in pixels.
@property (readonly, nonatomic) CGSize size;

#pragma mark - Export

/// Requests a Live Photo from the given resource URLs. The result handler will be called multiple times to deliver new PHLivePhoto instances with increasingly more content. If a placeholder image is provided, the result handler will first be invoked synchronously to deliver a live photo containing only the placeholder image. Subsequent invocations of the result handler will occur on the main queue.
//  The targetSize and contentMode parameters are used to resize the live photo content if needed. If targetSize is equal to CGRectZero, content will not be resized.
//  When using this method to provide content for a PHLivePhotoView, each live photo instance delivered via the result handler should be passed to -[PHLivePhotoView setLivePhoto:].
+ (PHLivePhotoRequestID)requestLivePhotoWithResourceFileURLs:(NSArray<NSURL *> *)fileURLs placeholderImage:(UIImage *__nullable)image targetSize:(CGSize)targetSize contentMode:(PHImageContentMode)contentMode resultHandler:(void(^)(PHLivePhoto *__nullable livePhoto, NSDictionary *info))resultHandler;

/// Cancels the loading of a PHLivePhoto. The request's completion handler will be called.
+ (void)cancelLivePhotoRequestWithRequestID:(PHLivePhotoRequestID)requestID;

@end


NS_ASSUME_NONNULL_END
