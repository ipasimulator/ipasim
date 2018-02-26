//
//  ARPlaneAnchor.h
//  ARKit
//
//  Copyright © 2016-2017 Apple Inc. All rights reserved.
//

#import <ARKit/ARAnchor.h>
#import <CoreGraphics/CoreGraphics.h>

NS_ASSUME_NONNULL_BEGIN

/**
 A value describing the alignment of a plane anchor.
 */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos)
typedef NS_ENUM(NSInteger, ARPlaneAnchorAlignment) {
    /** A plane that is horizontal with respect to gravity. */
    ARPlaneAnchorAlignmentHorizontal

} NS_SWIFT_NAME(ARPlaneAnchor.Alignment);

/**
 An anchor representing a planar surface in the world.
 @discussion Planes are defined in the X and Z direction, where Y is the surface’s normal.
 */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos)
@interface ARPlaneAnchor : ARAnchor

/**
 The alignment of the plane.
 */
@property (nonatomic, readonly) ARPlaneAnchorAlignment alignment;

/**
 The center of the plane in the anchor’s coordinate space.
 */
@property (nonatomic, readonly) vector_float3 center;

/**
 The extent of the plane in the anchor’s coordinate space.
 */
@property (nonatomic, readonly) vector_float3 extent;

/** Unavailable */
- (instancetype)initWithTransform:(matrix_float4x4)transform NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
