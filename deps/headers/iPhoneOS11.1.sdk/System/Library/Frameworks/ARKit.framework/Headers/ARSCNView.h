//
//  ARSCNView.h
//  ARKit
//
//  Copyright © 2016-2017 Apple Inc. All rights reserved.
//

#import <SceneKit/SceneKit.h>
#import <ARKit/ARSession.h>
#import <ARKit/ARHitTestResult.h>

@protocol ARSCNViewDelegate;

NS_ASSUME_NONNULL_BEGIN

/**
 A view that integrates ARSession rendering into SceneKit.
 
 @discussion The view draws the camera background, provides and updates a camera,
 manages nodes for anchors, and updates lighting.
 */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos)
@interface ARSCNView : SCNView

/**
 Specifies the renderer delegate.
 */
@property (nonatomic, weak, nullable) id<ARSCNViewDelegate> delegate;

/**
 The session that the view uses to update the scene.
 */
@property (nonatomic, strong) ARSession *session;

/**
 Specifies the scene of the view.
 */
@property(nonatomic, strong) SCNScene *scene;

/**
 Determines whether the view will update the scene’s lighting.
 
 @discussion When set, the view will automatically create and update lighting for 
 light estimates the session provides. Defaults to YES.
 */
@property(nonatomic) BOOL automaticallyUpdatesLighting;

/**
 Searches the scene hierarchy for an anchor associated with the provided node.
 @param node A node in the view’s scene.
 */
- (nullable ARAnchor *)anchorForNode:(SCNNode *)node;

/**
 Returns the node that has been mapped to a specific anchor.
 @param anchor An anchor with an existing node mapping.
 */
- (nullable SCNNode *)nodeForAnchor:(ARAnchor *)anchor;

/**
 Searches the current frame for objects corresponding to a point in the view.
 
 @discussion A 2D point in the view’s coordinate space can refer to any point along a line segment
 in the 3D coordinate space. Hit-testing is the process of finding objects in the world located along this line segment.
 @param point A point in the view’s coordinate system.
 @param types The types of results to search for.
 @return An array of all hit-test results sorted from nearest to farthest.
 */
- (NSArray<ARHitTestResult *> *)hitTest:(CGPoint)point types:(ARHitTestResultType)types;

@end


#pragma mark - ARSCNViewDelegate


API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos)
@protocol ARSCNViewDelegate <SCNSceneRendererDelegate, ARSessionObserver>
@optional

/**
 Implement this to provide a custom node for the given anchor.
 
 @discussion This node will automatically be added to the scene graph.
 If this method is not implemented, a node will be automatically created.
 If nil is returned the anchor will be ignored.
 @param renderer The renderer that will render the scene.
 @param anchor The added anchor.
 @return Node that will be mapped to the anchor or nil.
 */
- (nullable SCNNode *)renderer:(id <SCNSceneRenderer>)renderer nodeForAnchor:(ARAnchor *)anchor;

/**
 Called when a new node has been mapped to the given anchor.
 
 @param renderer The renderer that will render the scene.
 @param node The node that maps to the anchor.
 @param anchor The added anchor.
 */
- (void)renderer:(id <SCNSceneRenderer>)renderer didAddNode:(SCNNode *)node forAnchor:(ARAnchor *)anchor;

/**
 Called when a node will be updated with data from the given anchor.
 
 @param renderer The renderer that will render the scene.
 @param node The node that will be updated.
 @param anchor The anchor that was updated.
 */
- (void)renderer:(id <SCNSceneRenderer>)renderer willUpdateNode:(SCNNode *)node forAnchor:(ARAnchor *)anchor;

/**
 Called when a node has been updated with data from the given anchor.
 
 @param renderer The renderer that will render the scene.
 @param node The node that was updated.
 @param anchor The anchor that was updated.
 */
- (void)renderer:(id <SCNSceneRenderer>)renderer didUpdateNode:(SCNNode *)node forAnchor:(ARAnchor *)anchor;

/**
 Called when a mapped node has been removed from the scene graph for the given anchor.
 
 @param renderer The renderer that will render the scene.
 @param node The node that was removed.
 @param anchor The anchor that was removed.
 */
- (void)renderer:(id <SCNSceneRenderer>)renderer didRemoveNode:(SCNNode *)node forAnchor:(ARAnchor *)anchor;

@end


/**
 Extended debug options for an ARSCNView
 */
struct ARSCNDebugOptions {} API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos);

/** Show the world origin in the scene. */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos)
FOUNDATION_EXTERN const SCNDebugOptions ARSCNDebugOptionShowWorldOrigin NS_SWIFT_NAME(ARSCNDebugOptions.showWorldOrigin);

/** Show detected 3D feature points in the world. */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos)
FOUNDATION_EXTERN const SCNDebugOptions ARSCNDebugOptionShowFeaturePoints NS_SWIFT_NAME(ARSCNDebugOptions.showFeaturePoints);

NS_ASSUME_NONNULL_END
