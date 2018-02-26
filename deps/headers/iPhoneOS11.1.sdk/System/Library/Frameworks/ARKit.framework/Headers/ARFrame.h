//
//  ARFrame.h
//  ARKit
//
//  Copyright © 2016-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreVideo/CoreVideo.h>
#import <UIKit/UIApplication.h>
#import <simd/simd.h>
#import <ARKit/ARHitTestResult.h>

@class ARAnchor;
@class ARCamera;
@class ARLightEstimate;
@class ARPointCloud;
@class AVDepthData;

NS_ASSUME_NONNULL_BEGIN

/**
 An object encapsulating the state of everything being tracked for a given moment in time.
 @discussion The model provides a snapshot of all data needed to render a given frame.
 */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos)
@interface ARFrame : NSObject <NSCopying>

/**
 A timestamp identifying the frame.
 */
@property (nonatomic, readonly) NSTimeInterval timestamp;

/**
 The frame’s captured image.
 */
@property (nonatomic, readonly) CVPixelBufferRef capturedImage;

/**
 The frame’s captured depth data.
 
 @discussion Depth data is only provided with face tracking on frames where depth data was captured.
 */
@property (nonatomic, strong, readonly, nullable) AVDepthData *capturedDepthData;

/**
 A timestamp identifying the depth data.
 */
@property (nonatomic, readonly) NSTimeInterval capturedDepthDataTimestamp;

/**
 The camera used to capture the frame’s image.
 @discussion The camera provides the device’s position and orientation as well as camera parameters.
 */
@property (nonatomic, copy, readonly) ARCamera *camera;

/**
 A list of anchors in the scene.
 */
@property (nonatomic, copy, readonly) NSArray<ARAnchor *> *anchors;

/**
 A light estimate representing the light in the scene.
 @discussion Returns nil if there is no light estimation.
 */
@property (nonatomic, strong, nullable, readonly) ARLightEstimate *lightEstimate;

/**
 Feature points in the scene with respect to the frame’s origin.
 @discussion The feature points are only provided for configurations using world tracking.
 */
@property (nonatomic, strong, nullable, readonly) ARPointCloud *rawFeaturePoints;

/**
 Searches the frame for objects corresponding to a point in the captured image.
 
 @discussion A 2D point in the captured image’s coordinate space can refer to any point along a line segment
 in the 3D coordinate space. Hit-testing is the process of finding objects in the world located along this line segment.
 @param point A point in the image-space coordinate system of the captured image.
 Values should range from (0,0) - upper left corner to (1,1) - lower right corner.
 @param types The types of results to search for.
 @return An array of all hit-test results sorted from nearest to farthest.
 */
- (NSArray<ARHitTestResult *> *)hitTest:(CGPoint)point types:(ARHitTestResultType)types;

/**
 Returns a display transform for the provided viewport size and orientation.
 
 @discussion The display transform can be used to convert normalized points in the image-space coordinate system
 of the captured image to normalized points in the view’s coordinate space. The transform provides the correct rotation
 and aspect-fill for presenting the captured image in the given orientation and size.
 @param orientation The orientation of the viewport.
 @param viewportSize The size of the viewport.
 */
- (CGAffineTransform)displayTransformForOrientation:(UIInterfaceOrientation)orientation viewportSize:(CGSize)viewportSize;

/** Unavailable */
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
