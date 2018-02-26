//
//  WKInterfaceSKScene.h
//  WatchKit
//
//  Copyright © 2016 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>
#import <WatchKit/WKInterfaceObject.h>

NS_ASSUME_NONNULL_BEGIN

@class SKScene, SKTransition, SKTexture, SKNode;

WK_AVAILABLE_WATCHOS_ONLY(3.0)
@interface WKInterfaceSKScene : WKInterfaceObject

/**
 Pause the entire interface
 */
@property (nonatomic, getter = isPaused) BOOL paused;

/* Defines the desired rate for interface to render it's content.
 Actual rate maybe be limited by hardware or other software. */
@property (nonatomic) NSInteger preferredFramesPerSecond NS_AVAILABLE(10_12, 10_0);

/**
 Present an SKScene in the interface, replacing the current scene.
 
 @param scene the scene to present.
 */
- (void)presentScene:(nullable SKScene *)scene;

/**
 Present an SKScene in the interface, replacing the current scene.
 
 If there is currently a scene being presented in the interface, the transition is used to swap between them.
 
 @param scene the scene to present.
 @param transition the transition to use when presenting the scene.
 */
- (void)presentScene:(SKScene *)scene transition:(SKTransition *)transition;

/**
 The currently presented scene, otherwise nil. If in a transition, the 'incoming' scene is returned.
 */
@property (nonatomic, readonly, nullable) SKScene *scene;

/**
 Create an SKTexture containing a snapshot of how it would have been rendered in this interface.
 The texture is tightly cropped to the size of the node.
 @param node the node subtree to render to the texture.
 */
- (nullable SKTexture *)textureFromNode:(SKNode *)node;

/**
 Create an SKTexture containing a snapshot of how it would have been rendered in this interface.
 The texture is cropped to the specified rectangle
 @param node the node subtree to render to the texture.
 @param crop the rectangle to crop to
 */
- (nullable SKTexture *)textureFromNode:(SKNode *)node crop:(CGRect)crop;

@end

NS_ASSUME_NONNULL_END
