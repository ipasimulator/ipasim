//
//  WKInterfaceSCNScene.h
//  WatchKit
//
//  Copyright (c) 2016 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>
#import <WatchKit/WKInterfaceObject.h>
#import <SceneKit/SceneKit.h>

NS_ASSUME_NONNULL_BEGIN

WK_AVAILABLE_WATCHOS_ONLY(3.0)
@interface WKInterfaceSCNScene : WKInterfaceObject <SCNSceneRenderer>

/*!
 @property scene
 @abstract Specifies the scene of the receiver
 */
@property(nonatomic, retain, nullable) SCNScene *scene;

/*!
 @property snapshot
 @abstract Draws the contents of the view and returns them as a new image object
 @discussion This method is thread-safe and may be called at any time.
 */
- (UIImage *)snapshot;

/*!
 @property preferredFramesPerSecond
 @abstract The rate you want the view to redraw its contents.
 @discussion When your application sets its preferred frame rate, the view chooses a frame rate as close to that as possible based on the capabilities of the screen the view is displayed on. The actual frame rate chosen is usually a factor of the maximum refresh rate of the screen to provide a consistent frame rate. For example, if the maximum refresh rate of the screen is 60 frames per second, that is also the highest frame rate the view sets as the actual frame rate. However, if you ask for a lower frame rate, it might choose 30, 20, 15 or some other factor to be the actual frame rate. Your application should choose a frame rate that it can consistently maintain.
 The default value is 0 which means the display link will fire at the native cadence of the display hardware.
 */
@property(nonatomic) NSInteger preferredFramesPerSecond;

/*!
 @property antialiasingMode
 @abstract Defaults to SCNAntialiasingModeNone.
 */
@property(nonatomic) SCNAntialiasingMode antialiasingMode;

@end

NS_ASSUME_NONNULL_END
