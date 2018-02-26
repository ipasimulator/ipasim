//
//  PHAsset.h
//  Photos
//
//  Copyright (c) 2017 Apple Inc. All rights reserved.
//

#import <Photos/PHObject.h>
#import <Photos/PhotosTypes.h>
#import <Photos/PHFetchResult.h>
#import <Photos/PHPhotoLibrary.h>
#import <Photos/PhotosDefines.h>

#import <ImageIO/ImageIO.h>
#import <CoreLocation/CLLocation.h>


@class PHFetchOptions;
@class PHAssetCollection;
@class PHPerson;

NS_ASSUME_NONNULL_BEGIN

PHOTOS_CLASS_AVAILABLE_IOS_TVOS(8_0, 10_0) @interface PHAsset : PHObject

#pragma mark - Properties

// Playback style describes how the asset should be presented to the user (regardless of the backing media for that asset).  Use this value to choose the type of view and the appropriate APIs on the PHImageManager to display this asset
@property (nonatomic, assign, readonly) PHAssetPlaybackStyle playbackStyle PHOTOS_AVAILABLE_IOS_TVOS(11_0, 11_0);

@property (nonatomic, assign, readonly) PHAssetMediaType mediaType;
@property (nonatomic, assign, readonly) PHAssetMediaSubtype mediaSubtypes;

@property (nonatomic, assign, readonly) NSUInteger pixelWidth;
@property (nonatomic, assign, readonly) NSUInteger pixelHeight;

@property (nonatomic, strong, readonly, nullable) NSDate *creationDate;
@property (nonatomic, strong, readonly, nullable) NSDate *modificationDate;

@property (nonatomic, strong, readonly, nullable) CLLocation *location;

@property (nonatomic, assign, readonly) NSTimeInterval duration;

// a hidden asset will be excluded from moment collections, but may still be included in other smart or regular album collections
@property (nonatomic, assign, readonly, getter=isHidden) BOOL hidden;

@property (nonatomic, assign, readonly, getter=isFavorite) BOOL favorite;

@property (nonatomic, strong, readonly, nullable) NSString *burstIdentifier;
@property (nonatomic, assign, readonly) PHAssetBurstSelectionType burstSelectionTypes;
@property (nonatomic, assign, readonly) BOOL representsBurst;

@property (nonatomic, assign, readonly) PHAssetSourceType sourceType PHOTOS_AVAILABLE_IOS_TVOS(9_0, 10_0);

#pragma mark - Capabilities

- (BOOL)canPerformEditOperation:(PHAssetEditOperation)editOperation;

#pragma mark - Fetching assets

+ (PHFetchResult<PHAsset *> *)fetchAssetsInAssetCollection:(PHAssetCollection *)assetCollection options:(nullable PHFetchOptions *)options;
+ (PHFetchResult<PHAsset *> *)fetchAssetsWithLocalIdentifiers:(NSArray<NSString *> *)identifiers options:(nullable PHFetchOptions *)options; // includes hidden assets by default
+ (nullable PHFetchResult<PHAsset *> *)fetchKeyAssetsInAssetCollection:(PHAssetCollection *)assetCollection options:(nullable PHFetchOptions *)options;
+ (PHFetchResult<PHAsset *> *)fetchAssetsWithBurstIdentifier:(NSString *)burstIdentifier options:(nullable PHFetchOptions *)options;

// Fetches PHAssetSourceTypeUserLibrary assets by default (use includeAssetSourceTypes option to override)
+ (PHFetchResult<PHAsset *> *)fetchAssetsWithOptions:(nullable PHFetchOptions *)options;
+ (PHFetchResult<PHAsset *> *)fetchAssetsWithMediaType:(PHAssetMediaType)mediaType options:(nullable PHFetchOptions *)options;

// assetURLs are URLs retrieved from ALAsset's ALAssetPropertyAssetURL
+ (PHFetchResult<PHAsset *> *)fetchAssetsWithALAssetURLs:(NSArray<NSURL *> *)assetURLs options:(nullable PHFetchOptions *)options API_DEPRECATED("Will be removed in a future release", ios(8.0, 11.0), tvos(8.0, 11.0));

@end

NS_ASSUME_NONNULL_END
