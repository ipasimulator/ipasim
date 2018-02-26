//
//  SKDownload.h
//  StoreKit
//
//  Copyright (c) 2012 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <StoreKit/StoreKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class SKPaymentTransaction;

typedef NS_ENUM(NSInteger, SKDownloadState) {
    SKDownloadStateWaiting,     // Download is inactive, waiting to be downloaded
    SKDownloadStateActive,      // Download is actively downloading
    SKDownloadStatePaused,      // Download was paused by the user
    SKDownloadStateFinished,    // Download is finished, content is available
    SKDownloadStateFailed,      // Download failed
    SKDownloadStateCancelled,   // Download was cancelled
} NS_AVAILABLE_IOS(6_0);

SK_EXTERN NSTimeInterval SKDownloadTimeRemainingUnknown NS_AVAILABLE_IOS(6_0);

SK_EXTERN_CLASS_AVAILABLE(6_0) @interface SKDownload : NSObject

// State of the download
@property(nonatomic, readonly) SKDownloadState downloadState NS_AVAILABLE_IOS(6_0);

// Total size of the content, in bytes
@property(nonatomic, readonly) long long contentLength NS_AVAILABLE_IOS(6_0);

// Identifier for this content
@property(nonatomic, readonly) NSString *contentIdentifier NS_AVAILABLE_IOS(6_0);

// Location of the content data, if downloadState is SKDownloadStateFinished
@property(nonatomic, readonly, nullable) NSURL *contentURL NS_AVAILABLE_IOS(6_0);

// Content version
@property(nonatomic, readonly) NSString *contentVersion NS_AVAILABLE_IOS(6_0);

// Failure error, if downloadState is SKDownloadStateFailed
@property(nonatomic, readonly, nullable) NSError *error NS_AVAILABLE_IOS(6_0);

// Overall progress for the download [0..1]
@property(nonatomic, readonly) float progress NS_AVAILABLE_IOS(6_0);

// Estimated time remaining to complete the download, in seconds.  Value is SKDownloadTimeRemainingUnknown if estimate is unknownxx.
@property(nonatomic, readonly) NSTimeInterval timeRemaining NS_AVAILABLE_IOS(6_0);

// Transaction for this download
@property(nonatomic, readonly) SKPaymentTransaction *transaction NS_AVAILABLE_IOS(6_0);

@end

NS_ASSUME_NONNULL_END
