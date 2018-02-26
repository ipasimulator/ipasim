//
//  PHPhotoLibrary.h
//  Photos
//
//  Copyright (c) 2013 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Photos/PhotosDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class PHChange;

typedef NS_ENUM(NSInteger, PHAuthorizationStatus) {
    PHAuthorizationStatusNotDetermined = 0, // User has not yet made a choice with regards to this application
    PHAuthorizationStatusRestricted,        // This application is not authorized to access photo data.
                                            // The user cannot change this application’s status, possibly due to active restrictions
                                            //   such as parental controls being in place.
    PHAuthorizationStatusDenied,            // User has explicitly denied this application access to photos data.
    PHAuthorizationStatusAuthorized         // User has authorized this application to access photos data.
} PHOTOS_AVAILABLE_IOS_TVOS(8_0, 10_0);


PHOTOS_CLASS_AVAILABLE_IOS_TVOS(8_0, 10_0) @protocol PHPhotoLibraryChangeObserver <NSObject>
// This callback is invoked on an arbitrary serial queue. If you need this to be handled on a specific queue, you should redispatch appropriately
- (void)photoLibraryDidChange:(PHChange *)changeInstance;

@end

/*!
 @class        PHPhotoLibrary
 @abstract     A PHPhotoLibrary provides access to the metadata and image data for the photos, videos and related content in the user's photo library, including content from the Camera Roll, iCloud Shared, Photo Stream, imported, and synced from iTunes.
 @discussion   ...
 */
PHOTOS_CLASS_AVAILABLE_IOS_TVOS(8_0, 10_0) @interface PHPhotoLibrary : NSObject

+ (PHPhotoLibrary *)sharedPhotoLibrary;

+ (PHAuthorizationStatus)authorizationStatus;
+ (void)requestAuthorization:(void(^)(PHAuthorizationStatus status))handler;

#pragma mark - Applying Changes

// handlers are invoked on an arbitrary serial queue
// Nesting change requests will throw an exception
- (void)performChanges:(dispatch_block_t)changeBlock completionHandler:(nullable void(^)(BOOL success, NSError *__nullable error))completionHandler;
- (BOOL)performChangesAndWait:(dispatch_block_t)changeBlock error:(NSError *__autoreleasing *)error;

#pragma mark - Change Handling

- (void)registerChangeObserver:(id<PHPhotoLibraryChangeObserver>)observer;
- (void)unregisterChangeObserver:(id<PHPhotoLibraryChangeObserver>)observer;

@end

NS_ASSUME_NONNULL_END
