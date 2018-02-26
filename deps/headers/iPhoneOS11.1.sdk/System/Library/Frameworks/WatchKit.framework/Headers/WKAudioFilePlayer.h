//
//  WKAudioFilePlayer.h
//  WatchKit
//
//  Copyright (c) 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>

/*!
 @class		WKAudioFilePlayer
 
 @abstract
 WatchKit corollary to AVFoundation AVPlayer class
 
 @discussion
 This class provides the functionality of AVPlayer for Watch OS apps. Only file-based assets are allowed.
 */

@class WKAudioFilePlayerItem;

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, WKAudioFilePlayerStatus) {
    WKAudioFilePlayerStatusUnknown,
    WKAudioFilePlayerStatusReadyToPlay,
    WKAudioFilePlayerStatusFailed
} WK_AVAILABLE_WATCHOS_ONLY(2.0);

WK_AVAILABLE_WATCHOS_ONLY(2.0)
@interface WKAudioFilePlayer : NSObject

- (instancetype)init NS_UNAVAILABLE;

+ (instancetype)playerWithPlayerItem:(WKAudioFilePlayerItem *)item;

- (void)play;
- (void)pause;

- (void)replaceCurrentItemWithPlayerItem:(nullable WKAudioFilePlayerItem *)item;

@property(nonatomic, readonly, nullable) WKAudioFilePlayerItem *currentItem;

@property (nonatomic, readonly) WKAudioFilePlayerStatus status;
@property (nonatomic, readonly, nullable) NSError *error;

/* indicates the current rate of playback; 0.0 means "stopped", 1.0 means "play at the natural rate of the current item" */
@property (nonatomic) float rate;

@property (nonatomic, readonly) NSTimeInterval currentTime;

@end


/*!
 @class		WKAudioFileQueuePlayer
 
 @abstract
 WatchKit corollary to AVFoundation AVQueuePlayer class
 
 @discussion
 This class provides the functionality of AVQueuePlayer for Watch OS apps. Only file-based assets are allowed.
 */

WK_AVAILABLE_WATCHOS_ONLY(2.0)
@interface WKAudioFileQueuePlayer : WKAudioFilePlayer
+ (instancetype)queuePlayerWithItems:(NSArray<WKAudioFilePlayerItem *> *)items;

- (void)advanceToNextItem;

- (void)appendItem:(WKAudioFilePlayerItem *)item;

- (void)removeItem:(WKAudioFilePlayerItem *)item;

- (void)removeAllItems;

@property(nonatomic, readonly) NSArray<WKAudioFilePlayerItem *> *items;

@end

NS_ASSUME_NONNULL_END
