//
//  UIEvent.h
//  UIKit
//
//  Copyright (c) 2005-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class UIWindow, UIView, UIGestureRecognizer, UITouch;

typedef NS_ENUM(NSInteger, UIEventType) {
    UIEventTypeTouches,
    UIEventTypeMotion,
    UIEventTypeRemoteControl,
    UIEventTypePresses NS_ENUM_AVAILABLE_IOS(9_0),
};

typedef NS_ENUM(NSInteger, UIEventSubtype) {
    // available in iPhone OS 3.0
    UIEventSubtypeNone                              = 0,
    
    // for UIEventTypeMotion, available in iPhone OS 3.0
    UIEventSubtypeMotionShake                       = 1,
    
    // for UIEventTypeRemoteControl, available in iOS 4.0
    UIEventSubtypeRemoteControlPlay                 = 100,
    UIEventSubtypeRemoteControlPause                = 101,
    UIEventSubtypeRemoteControlStop                 = 102,
    UIEventSubtypeRemoteControlTogglePlayPause      = 103,
    UIEventSubtypeRemoteControlNextTrack            = 104,
    UIEventSubtypeRemoteControlPreviousTrack        = 105,
    UIEventSubtypeRemoteControlBeginSeekingBackward = 106,
    UIEventSubtypeRemoteControlEndSeekingBackward   = 107,
    UIEventSubtypeRemoteControlBeginSeekingForward  = 108,
    UIEventSubtypeRemoteControlEndSeekingForward    = 109,
};


NS_CLASS_AVAILABLE_IOS(2_0) @interface UIEvent : NSObject

@property(nonatomic,readonly) UIEventType     type NS_AVAILABLE_IOS(3_0);
@property(nonatomic,readonly) UIEventSubtype  subtype NS_AVAILABLE_IOS(3_0);

@property(nonatomic,readonly) NSTimeInterval  timestamp;

#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly, nullable) NSSet <UITouch *> *allTouches;
#else
- (nullable NSSet <UITouch *> *)allTouches;
#endif
- (nullable NSSet <UITouch *> *)touchesForWindow:(UIWindow *)window;
- (nullable NSSet <UITouch *> *)touchesForView:(UIView *)view;
- (nullable NSSet <UITouch *> *)touchesForGestureRecognizer:(UIGestureRecognizer *)gesture NS_AVAILABLE_IOS(3_2);

// An array of auxiliary UITouch’s for the touch events that did not get delivered for a given main touch. This also includes an auxiliary version of the main touch itself.
- (nullable NSArray <UITouch *> *)coalescedTouchesForTouch:(UITouch *)touch NS_AVAILABLE_IOS(9_0);

// An array of auxiliary UITouch’s for touch events that are predicted to occur for a given main touch. These predictions may not exactly match the real behavior of the touch as it moves, so they should be interpreted as an estimate.
- (nullable NSArray <UITouch *> *)predictedTouchesForTouch:(UITouch *)touch NS_AVAILABLE_IOS(9_0);

@end

NS_ASSUME_NONNULL_END
