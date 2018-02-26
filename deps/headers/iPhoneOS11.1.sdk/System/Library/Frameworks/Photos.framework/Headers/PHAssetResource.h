//
//  PHAssetResource.h
//  Photos
//
//  Copyright © 2015 Apple Inc. All rights reserved.
//

#import <Photos/PhotosTypes.h>
#import <Photos/PhotosDefines.h>

@class PHAsset;
@class PHLivePhoto;

NS_ASSUME_NONNULL_BEGIN

PHOTOS_CLASS_AVAILABLE_IOS_TVOS(9_0, 10_0) @interface PHAssetResource : NSObject

@property (nonatomic, assign, readonly) PHAssetResourceType type;
@property (nonatomic, copy, readonly) NSString *assetLocalIdentifier;
@property (nonatomic, copy, readonly) NSString *uniformTypeIdentifier;
@property (nonatomic, copy, readonly) NSString *originalFilename;

#pragma mark - Getting resources

+ (NSArray<PHAssetResource *> *)assetResourcesForAsset:(PHAsset *)asset;
+ (NSArray<PHAssetResource *> *)assetResourcesForLivePhoto:(PHLivePhoto *)livePhoto PHOTOS_AVAILABLE_IOS_TVOS(9_1, 10_0);

@end

NS_ASSUME_NONNULL_END
