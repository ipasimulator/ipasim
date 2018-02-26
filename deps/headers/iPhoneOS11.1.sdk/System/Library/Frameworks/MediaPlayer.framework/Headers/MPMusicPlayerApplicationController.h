//
//  MPMusicPlayerApplicationController.h
//  MediaPlayer
//
//  Copyright © 2016-2017 Apple Inc. All rights reserved.
//

#import <MediaPlayer/MediaPlayer.h>
#import <MediaPlayer/MPMusicPlayerController.h>

NS_ASSUME_NONNULL_BEGIN

MP_API(ios(10.3))
MP_PROHIBITED(tvos)
@interface MPMusicPlayerControllerQueue : NSObject

- (instancetype)init NS_UNAVAILABLE;

@property (nonatomic, copy, readonly) NSArray<MPMediaItem *> *items;

@end

MP_API(ios(10.3))
MP_PROHIBITED(tvos)
@interface MPMusicPlayerControllerMutableQueue : MPMusicPlayerControllerQueue

- (void)insertQueueDescriptor:(MPMusicPlayerQueueDescriptor *)queueDescriptor afterItem:(nullable MPMediaItem *)afterItem;
- (void)removeItem:(MPMediaItem *)item;

@end

MP_API(ios(10.3))
MP_PROHIBITED(tvos)
@interface MPMusicPlayerApplicationController : MPMusicPlayerController

- (void)performQueueTransaction:(void (^)(MPMusicPlayerControllerMutableQueue *queue))queueTransaction completionHandler:(void (^)(MPMusicPlayerControllerQueue *queue, NSError *_Nullable error))completionHandler;

@end

// Posted when the queue changes
MP_EXTERN NSString * const MPMusicPlayerControllerQueueDidChangeNotification MP_PROHIBITED(tvos);

NS_ASSUME_NONNULL_END
