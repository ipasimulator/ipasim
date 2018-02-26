//
//  UIWindow.h
//  UIKit
//
//  Copyright (c) 2005-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UIKit/UIView.h>
#import <UIKit/UIApplication.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

typedef CGFloat UIWindowLevel;

@class UIEvent, UIScreen, NSUndoManager, UIViewController;

NS_CLASS_AVAILABLE_IOS(2_0) @interface UIWindow : UIView

@property(nonatomic,strong) UIScreen *screen NS_AVAILABLE_IOS(3_2);  // default is [UIScreen mainScreen]. changing the screen may be an expensive operation and should not be done in performance-sensitive code

@property(nonatomic) UIWindowLevel windowLevel;                   // default = 0.0
@property(nonatomic,readonly,getter=isKeyWindow) BOOL keyWindow;
- (void)becomeKeyWindow;                               // override point for subclass. Do not call directly
- (void)resignKeyWindow;                               // override point for subclass. Do not call directly

- (void)makeKeyWindow;
- (void)makeKeyAndVisible;                             // convenience. most apps call this to show the main window and also make it key. otherwise use view hidden property

@property(nullable, nonatomic,strong) UIViewController *rootViewController NS_AVAILABLE_IOS(4_0);  // default is nil

- (void)sendEvent:(UIEvent *)event;                    // called by UIApplication to dispatch events to views inside the window

- (CGPoint)convertPoint:(CGPoint)point toWindow:(nullable UIWindow *)window;    // can be used to convert to another window
- (CGPoint)convertPoint:(CGPoint)point fromWindow:(nullable UIWindow *)window;  // pass in nil to mean screen
- (CGRect)convertRect:(CGRect)rect toWindow:(nullable UIWindow *)window;
- (CGRect)convertRect:(CGRect)rect fromWindow:(nullable UIWindow *)window;

@end

UIKIT_EXTERN const UIWindowLevel UIWindowLevelNormal;
UIKIT_EXTERN const UIWindowLevel UIWindowLevelAlert;
UIKIT_EXTERN const UIWindowLevel UIWindowLevelStatusBar __TVOS_PROHIBITED;

UIKIT_EXTERN NSNotificationName const UIWindowDidBecomeVisibleNotification; // nil
UIKIT_EXTERN NSNotificationName const UIWindowDidBecomeHiddenNotification;  // nil
UIKIT_EXTERN NSNotificationName const UIWindowDidBecomeKeyNotification;     // nil
UIKIT_EXTERN NSNotificationName const UIWindowDidResignKeyNotification;     // nil

// Each notification includes a nil object and a userInfo dictionary containing the
// begining and ending keyboard frame in screen coordinates. Use the various UIView and
// UIWindow convertRect facilities to get the frame in the desired coordinate system.
// Animation key/value pairs are only available for the "will" family of notification.
UIKIT_EXTERN NSNotificationName const UIKeyboardWillShowNotification __TVOS_PROHIBITED;
UIKIT_EXTERN NSNotificationName const UIKeyboardDidShowNotification __TVOS_PROHIBITED;
UIKIT_EXTERN NSNotificationName const UIKeyboardWillHideNotification __TVOS_PROHIBITED;
UIKIT_EXTERN NSNotificationName const UIKeyboardDidHideNotification __TVOS_PROHIBITED;

UIKIT_EXTERN NSString *const UIKeyboardFrameBeginUserInfoKey        NS_AVAILABLE_IOS(3_2) __TVOS_PROHIBITED; // NSValue of CGRect
UIKIT_EXTERN NSString *const UIKeyboardFrameEndUserInfoKey          NS_AVAILABLE_IOS(3_2) __TVOS_PROHIBITED; // NSValue of CGRect
UIKIT_EXTERN NSString *const UIKeyboardAnimationDurationUserInfoKey NS_AVAILABLE_IOS(3_0) __TVOS_PROHIBITED; // NSNumber of double
UIKIT_EXTERN NSString *const UIKeyboardAnimationCurveUserInfoKey    NS_AVAILABLE_IOS(3_0) __TVOS_PROHIBITED; // NSNumber of NSUInteger (UIViewAnimationCurve)
UIKIT_EXTERN NSString *const UIKeyboardIsLocalUserInfoKey           NS_AVAILABLE_IOS(9_0) __TVOS_PROHIBITED; // NSNumber of BOOL

// Like the standard keyboard notifications above, these additional notifications include
// a nil object and begin/end frames of the keyboard in screen coordinates in the userInfo dictionary.
UIKIT_EXTERN NSNotificationName const UIKeyboardWillChangeFrameNotification  NS_AVAILABLE_IOS(5_0) __TVOS_PROHIBITED;
UIKIT_EXTERN NSNotificationName const UIKeyboardDidChangeFrameNotification   NS_AVAILABLE_IOS(5_0) __TVOS_PROHIBITED;

// These keys are superseded by UIKeyboardFrameBeginUserInfoKey and UIKeyboardFrameEndUserInfoKey.
UIKIT_EXTERN NSString *const UIKeyboardCenterBeginUserInfoKey   NS_DEPRECATED_IOS(2_0, 3_2) __TVOS_PROHIBITED;
UIKIT_EXTERN NSString *const UIKeyboardCenterEndUserInfoKey     NS_DEPRECATED_IOS(2_0, 3_2) __TVOS_PROHIBITED;
UIKIT_EXTERN NSString *const UIKeyboardBoundsUserInfoKey        NS_DEPRECATED_IOS(2_0, 3_2) __TVOS_PROHIBITED;

NS_ASSUME_NONNULL_END
