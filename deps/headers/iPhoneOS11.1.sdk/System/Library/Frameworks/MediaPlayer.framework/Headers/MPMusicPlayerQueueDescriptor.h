//
//  MPMusicPlayerQueueDescriptor.h
//  MediaPlayerFramework
//
//  Copyright © 2016-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <MediaPlayer/MediaPlayerDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class MPMediaItem, MPMediaItemCollection, MPMediaQuery;

MP_API(ios(10.1))
MP_PROHIBITED(tvos)
@interface MPMusicPlayerQueueDescriptor : NSObject<NSSecureCoding>

@end

MP_API(ios(10.1))
MP_PROHIBITED(tvos)
@interface MPMusicPlayerMediaItemQueueDescriptor : MPMusicPlayerQueueDescriptor

- (instancetype)initWithQuery:(MPMediaQuery *)query;
- (instancetype)initWithItemCollection:(MPMediaItemCollection *)itemCollection;

@property (nonatomic, copy, readonly) MPMediaQuery *query;
@property (nonatomic, strong, readonly) MPMediaItemCollection *itemCollection;
@property (nonatomic, strong, nullable) MPMediaItem *startItem;

- (void)setStartTime:(NSTimeInterval)startTime forItem:(MPMediaItem *)mediaItem;
- (void)setEndTime:(NSTimeInterval)endTime forItem:(MPMediaItem *)mediaItem;

@end

MP_API(ios(10.1))
MP_PROHIBITED(tvos)
@interface MPMusicPlayerStoreQueueDescriptor : MPMusicPlayerQueueDescriptor

- (instancetype)initWithStoreIDs:(NSArray<NSString *> *)storeIDs;

@property (nonatomic, copy, nullable) NSArray<NSString *> *storeIDs;
@property (nonatomic, copy, nullable) NSString *startItemID;

- (void)setStartTime:(NSTimeInterval)startTime forItemWithStoreID:(NSString *)storeID;
- (void)setEndTime:(NSTimeInterval)endTime forItemWithStoreID:(NSString *)storeID;

@end

MP_API(ios(11.0))
MP_PROHIBITED(tvos)
@interface MPMusicPlayerPlayParameters : NSObject<NSSecureCoding>

- (instancetype)init NS_UNAVAILABLE;
- (nullable instancetype)initWithDictionary:(NSDictionary<NSString *, id> *)dictionary;

@property (nonatomic, copy, readonly) NSDictionary<NSString *, id> *dictionary;

@end

MP_API(ios(11.0))
MP_PROHIBITED(tvos)
@interface MPMusicPlayerPlayParametersQueueDescriptor : MPMusicPlayerQueueDescriptor

- (instancetype)init NS_UNAVAILABLE;
- (instancetype)initWithPlayParametersQueue:(NSArray<MPMusicPlayerPlayParameters *> *)playParametersQueue;

@property (nonatomic, copy) NSArray<MPMusicPlayerPlayParameters *> *playParametersQueue;
@property (nonatomic, strong, nullable) MPMusicPlayerPlayParameters *startItemPlayParameters;

- (void)setStartTime:(NSTimeInterval)startTime forItemWithPlayParameters:(MPMusicPlayerPlayParameters *)playParameters;
- (void)setEndTime:(NSTimeInterval)endTime forItemWithPlayParameters:(MPMusicPlayerPlayParameters *)playParameters;

@end

NS_ASSUME_NONNULL_END
