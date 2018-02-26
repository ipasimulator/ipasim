//
//  ARAnchor.h
//  ARKit
//
//  Copyright © 2016-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <simd/simd.h>

NS_ASSUME_NONNULL_BEGIN

/**
 Object representing a physical location and orientation in 3D space.
 */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos)
@interface ARAnchor : NSObject <NSCopying>

/**
 Unique identifier of the anchor.
 */
@property (nonatomic, readonly) NSUUID *identifier;

/**
 The transformation matrix that defines the anchor’s rotation, translation and scale in world coordinates.
 */
@property (nonatomic, readonly) matrix_float4x4 transform;

/**
 Initializes a new anchor object.
 @param transform The transformation matrix that defines the anchor’s rotation, translation and scale in world coordinates.
 */
- (instancetype)initWithTransform:(matrix_float4x4)transform;

/** Unavailable */
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

/**
 A real world object or location in the scene that is being tracked.
 */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos)
@protocol ARTrackable <NSObject>

/**
 Tracking state of the anchor
 @discussion The isTracked value is used to determine the anchor transform’s validity. When the object being tracked is no longer detected in the
 camera image, its anchor will return NO for isTracked.
 */
@property (nonatomic, readonly) BOOL isTracked;

@end

NS_ASSUME_NONNULL_END
