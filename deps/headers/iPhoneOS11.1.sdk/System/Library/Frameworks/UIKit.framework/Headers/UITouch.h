//
//  UITouch.h
//  UIKit
//
//  Copyright (c) 2007-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class UIWindow, UIView, UIGestureRecognizer;

typedef NS_ENUM(NSInteger, UITouchPhase) {
    UITouchPhaseBegan,             // whenever a finger touches the surface.
    UITouchPhaseMoved,             // whenever a finger moves on the surface.
    UITouchPhaseStationary,        // whenever a finger is touching the surface but hasn't moved since the previous event.
    UITouchPhaseEnded,             // whenever a finger leaves the surface.
    UITouchPhaseCancelled,         // whenever a touch doesn't end but we need to stop tracking (e.g. putting device to face)
};

typedef NS_ENUM(NSInteger, UIForceTouchCapability) {
    UIForceTouchCapabilityUnknown = 0,
    UIForceTouchCapabilityUnavailable = 1,
    UIForceTouchCapabilityAvailable = 2
};

typedef NS_ENUM(NSInteger, UITouchType) {
    UITouchTypeDirect,                       // A direct touch from a finger (on a screen)
    UITouchTypeIndirect,                     // An indirect touch (not a screen)
    UITouchTypeStylus NS_AVAILABLE_IOS(9_1), // A touch from a stylus
} NS_ENUM_AVAILABLE_IOS(9_0);

typedef NS_OPTIONS(NSInteger, UITouchProperties) {
    UITouchPropertyForce = (1UL << 0),
    UITouchPropertyAzimuth = (1UL << 1),
    UITouchPropertyAltitude = (1UL << 2),
    UITouchPropertyLocation = (1UL << 3), // For predicted Touches
} NS_AVAILABLE_IOS(9_1);

NS_CLASS_AVAILABLE_IOS(2_0) @interface UITouch : NSObject

@property(nonatomic,readonly) NSTimeInterval      timestamp;
@property(nonatomic,readonly) UITouchPhase        phase;
@property(nonatomic,readonly) NSUInteger          tapCount;   // touch down within a certain point within a certain amount of time
@property(nonatomic,readonly) UITouchType         type NS_AVAILABLE_IOS(9_0);

// majorRadius and majorRadiusTolerance are in points
// The majorRadius will be accurate +/- the majorRadiusTolerance
@property(nonatomic,readonly) CGFloat majorRadius NS_AVAILABLE_IOS(8_0);
@property(nonatomic,readonly) CGFloat majorRadiusTolerance NS_AVAILABLE_IOS(8_0);

@property(nullable,nonatomic,readonly,strong) UIWindow                        *window;
@property(nullable,nonatomic,readonly,strong) UIView                          *view;
@property(nullable,nonatomic,readonly,copy)   NSArray <UIGestureRecognizer *> *gestureRecognizers NS_AVAILABLE_IOS(3_2);

- (CGPoint)locationInView:(nullable UIView *)view;
- (CGPoint)previousLocationInView:(nullable UIView *)view;

// Use these methods to gain additional precision that may be available from touches.
// Do not use precise locations for hit testing. A touch may hit test inside a view, yet have a precise location that lies just outside.
- (CGPoint)preciseLocationInView:(nullable UIView *)view NS_AVAILABLE_IOS(9_1);
- (CGPoint)precisePreviousLocationInView:(nullable UIView *)view NS_AVAILABLE_IOS(9_1);

// Force of the touch, where 1.0 represents the force of an average touch
@property(nonatomic,readonly) CGFloat force NS_AVAILABLE_IOS(9_0);
// Maximum possible force with this input mechanism
@property(nonatomic,readonly) CGFloat maximumPossibleForce NS_AVAILABLE_IOS(9_0);

// Azimuth angle. Valid only for stylus touch types. Zero radians points along the positive X axis.
// Passing a nil for the view parameter will return the azimuth relative to the touch's window.
- (CGFloat)azimuthAngleInView:(nullable UIView *)view NS_AVAILABLE_IOS(9_1);
// A unit vector that points in the direction of the azimuth angle. Valid only for stylus touch types.
// Passing nil for the view parameter will return a unit vector relative to the touch's window.
- (CGVector)azimuthUnitVectorInView:(nullable UIView *)view NS_AVAILABLE_IOS(9_1);

// Altitude angle. Valid only for stylus touch types.
// Zero radians indicates that the stylus is parallel to the screen surface,
// while M_PI/2 radians indicates that it is normal to the screen surface.
@property(nonatomic,readonly) CGFloat altitudeAngle NS_AVAILABLE_IOS(9_1);

// An index which allows you to correlate updates with the original touch.
// Is only guaranteed non-nil if this UITouch expects or is an update.
@property(nonatomic,readonly) NSNumber * _Nullable estimationUpdateIndex NS_AVAILABLE_IOS(9_1);
// A set of properties that has estimated values
// Only denoting properties that are currently estimated
@property(nonatomic,readonly) UITouchProperties estimatedProperties NS_AVAILABLE_IOS(9_1);
// A set of properties that expect to have incoming updates in the future.
// If no updates are expected for an estimated property the current value is our final estimate.
// This happens e.g. for azimuth/altitude values when entering from the edges
@property(nonatomic,readonly) UITouchProperties estimatedPropertiesExpectingUpdates NS_AVAILABLE_IOS(9_1);


@end

NS_ASSUME_NONNULL_END
