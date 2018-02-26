//
//  PHFetchResult.h
//  Photos
//
//  Copyright (c) 2013 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Photos/PhotosTypes.h>
#import <Photos/PhotosDefines.h>

NS_ASSUME_NONNULL_BEGIN

// Accessing fetched results (fetches objects from the backing store in chunks on demand rather than all at once)
// Fetched objects will be kept in a cache and purged under memory pressure
PHOTOS_CLASS_AVAILABLE_IOS_TVOS(8_0, 10_0) @interface PHFetchResult<ObjectType> : NSObject <NSCopying, NSFastEnumeration>

@property (readonly) NSUInteger count;
- (ObjectType)objectAtIndex:(NSUInteger)index;
- (ObjectType)objectAtIndexedSubscript:(NSUInteger)idx;

- (BOOL)containsObject:(ObjectType)anObject;

- (NSUInteger)indexOfObject:(ObjectType)anObject;
- (NSUInteger)indexOfObject:(ObjectType)anObject inRange:(NSRange)range;

@property (nonatomic, readonly, nullable) ObjectType firstObject;
@property (nonatomic, readonly, nullable) ObjectType lastObject;

- (NSArray<ObjectType> *)objectsAtIndexes:(NSIndexSet *)indexes;

- (void)enumerateObjectsUsingBlock:(void (^)(ObjectType obj, NSUInteger idx, BOOL *stop))block;
- (void)enumerateObjectsWithOptions:(NSEnumerationOptions)opts usingBlock:(void (^)(ObjectType obj, NSUInteger idx, BOOL *stop))block;
- (void)enumerateObjectsAtIndexes:(NSIndexSet *)s options:(NSEnumerationOptions)opts usingBlock:(void (^)(ObjectType obj, NSUInteger idx, BOOL *stop))block;

- (NSUInteger)countOfAssetsWithMediaType:(PHAssetMediaType)mediaType;

@end

NS_ASSUME_NONNULL_END
