//
//  WKAudioFilePlayerItem.h
//  WatchKit
//
//  Copyright (c) 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>

/*!
 @class		WKAudioFilePlayerItem
 
 @abstract
 WatchKit corollary to AVFoundation AVPlayerItem class
 
 @discussion
 This class provides the functionality of AVPlayerItem for Watch OS apps. Only file-based assets are allowed.
 */

@class WKAudioFileAsset;

NS_ASSUME_NONNULL_BEGIN

WKI_EXTERN NSString *const WKAudioFilePlayerItemTimeJumpedNotification WK_AVAILABLE_WATCHOS_ONLY(2.0);
WKI_EXTERN NSString *const WKAudioFilePlayerItemDidPlayToEndTimeNotification WK_AVAILABLE_WATCHOS_ONLY(2.0);
WKI_EXTERN NSString *const WKAudioFilePlayerItemFailedToPlayToEndTimeNotification WK_AVAILABLE_WATCHOS_ONLY(2.0);

typedef NS_ENUM(NSInteger, WKAudioFilePlayerItemStatus) {
    WKAudioFilePlayerItemStatusUnknown,
    WKAudioFilePlayerItemStatusReadyToPlay,
    WKAudioFilePlayerItemStatusFailed
} WK_AVAILABLE_WATCHOS_ONLY(2.0);

WK_AVAILABLE_WATCHOS_ONLY(2.0)
@interface WKAudioFilePlayerItem : NSObject

- (instancetype)init NS_UNAVAILABLE;

+ (WKAudioFilePlayerItem *)playerItemWithAsset:(WKAudioFileAsset *)asset;

@property (nonatomic, readonly) WKAudioFileAsset *asset;
@property (nonatomic, readonly) WKAudioFilePlayerItemStatus status;
@property (nonatomic, readonly, nullable) NSError *error;
@property (nonatomic, readonly) NSTimeInterval currentTime;

- (void)setCurrentTime:(NSTimeInterval)currentTime WK_AVAILABLE_WATCHOS_ONLY(3.2);

@end

NS_ASSUME_NONNULL_END
