//
//  UIUserNotificationSettings.h
//  UIKit
//
//  Copyright (c) 2007-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class UIUserNotificationCategory;
@class UIUserNotificationAction;

typedef NS_OPTIONS(NSUInteger, UIUserNotificationType) {
    UIUserNotificationTypeNone    = 0,      // the application may not present any UI upon a notification being received
    UIUserNotificationTypeBadge   = 1 << 0, // the application may badge its icon upon a notification being received
    UIUserNotificationTypeSound   = 1 << 1, // the application may play a sound upon a notification being received
    UIUserNotificationTypeAlert   = 1 << 2, // the application may display an alert upon a notification being received
} NS_ENUM_DEPRECATED_IOS(8_0, 10_0, "Use UserNotifications Framework's UNAuthorizationOptions") __TVOS_PROHIBITED;

typedef NS_ENUM(NSUInteger, UIUserNotificationActionBehavior) {
    UIUserNotificationActionBehaviorDefault,        // the default action behavior
    UIUserNotificationActionBehaviorTextInput       // system provided action behavior, allows text input from the user
} NS_ENUM_DEPRECATED_IOS(9_0, 10_0, "Use UserNotifications Framework's UNNotificationAction or UNTextInputNotificationAction") __TVOS_PROHIBITED;

typedef NS_ENUM(NSUInteger, UIUserNotificationActivationMode) {
    UIUserNotificationActivationModeForeground, // activates the application in the foreground
    UIUserNotificationActivationModeBackground  // activates the application in the background, unless it's already in the foreground
} NS_ENUM_DEPRECATED_IOS(8_0, 10_0, "Use UserNotifications Framework's UNNotificationActionOptions") __TVOS_PROHIBITED;

typedef NS_ENUM(NSUInteger, UIUserNotificationActionContext) {
    UIUserNotificationActionContextDefault,  // the default context of a notification action
    UIUserNotificationActionContextMinimal   // the context of a notification action when space is limited
} NS_ENUM_DEPRECATED_IOS(8_0, 10_0, "Use UserNotifications Framework's -[UNNotificationCategory actions] or -[UNNotificationCategory minimalActions]") __TVOS_PROHIBITED;

UIKIT_EXTERN NSString *const UIUserNotificationTextInputActionButtonTitleKey NS_DEPRECATED_IOS(9_0, 10_0, "Use UserNotifications Framework's -[UNTextInputNotificationAction textInputButtonTitle]") __TVOS_PROHIBITED;

UIKIT_EXTERN NSString *const UIUserNotificationActionResponseTypedTextKey NS_DEPRECATED_IOS(9_0, 10_0, "Use UserNotifications Framework's -[UNTextInputNotificationResponse userText]") __TVOS_PROHIBITED;

NS_CLASS_DEPRECATED_IOS(8_0, 10_0, "Use UserNotifications Framework's UNNotificationSettings") __TVOS_PROHIBITED
@interface UIUserNotificationSettings : NSObject

// categories may be nil or an empty set if custom user notification actions will not be used
+ (instancetype)settingsForTypes:(UIUserNotificationType)types
                      categories:(nullable NSSet<UIUserNotificationCategory *> *)categories; // instances of UIUserNotificationCategory

@property (nonatomic, readonly) UIUserNotificationType types;

// The set of UIUserNotificationCategory objects that describe the actions to show when a user notification is presented
@property (nullable, nonatomic, copy, readonly) NSSet<UIUserNotificationCategory *> *categories;

@end

NS_CLASS_DEPRECATED_IOS(8_0, 10_0, "Use UserNotifications Framework's UNNotificationCategory") __TVOS_PROHIBITED
@interface UIUserNotificationCategory : NSObject <NSCopying, NSMutableCopying, NSSecureCoding>

- (instancetype)init NS_DESIGNATED_INITIALIZER __TVOS_PROHIBITED;
- (nullable instancetype)initWithCoder:(NSCoder *)aDecoder NS_DESIGNATED_INITIALIZER __TVOS_PROHIBITED;

// The category identifier passed in a UILocalNotification or a remote notification payload
@property (nullable, nonatomic, copy, readonly) NSString *identifier __TVOS_PROHIBITED;

// UIUserNotificationActions in the order to be displayed for the specified context
- (nullable NSArray<UIUserNotificationAction *> *)actionsForContext:(UIUserNotificationActionContext)context __TVOS_PROHIBITED;

@end

NS_CLASS_DEPRECATED_IOS(8_0, 10_0, "Use UserNotifications Framework's UNNotificationCategory") __TVOS_PROHIBITED
@interface UIMutableUserNotificationCategory : UIUserNotificationCategory

// The category identifier passed in a UILocalNotification or a remote notification payload
@property (nullable, nonatomic, copy) NSString *identifier;

// Sets the UIUserNotificationActions in the order to be displayed for the specified context
- (void)setActions:(nullable NSArray<UIUserNotificationAction *> *)actions forContext:(UIUserNotificationActionContext)context;

@end

NS_CLASS_DEPRECATED_IOS(8_0, 10_0, "Use UserNotifications Framework's UNNotificationAction") __TVOS_PROHIBITED
@interface UIUserNotificationAction : NSObject <NSCopying, NSMutableCopying, NSSecureCoding>

- (instancetype)init NS_DESIGNATED_INITIALIZER __TVOS_PROHIBITED;
- (nullable instancetype)initWithCoder:(NSCoder *)aDecoder NS_DESIGNATED_INITIALIZER __TVOS_PROHIBITED;

// The unique identifier for this action.
@property (nullable, nonatomic, copy, readonly) NSString *identifier __TVOS_PROHIBITED;

// The localized title to display for this action.
@property (nullable, nonatomic, copy, readonly) NSString *title __TVOS_PROHIBITED;

// The behavior of this action when the user activates it.
@property (nonatomic, assign, readonly) UIUserNotificationActionBehavior behavior NS_AVAILABLE_IOS(9_0) __TVOS_PROHIBITED;

// Parameters that can be used by some types of actions.
@property (nonatomic, copy, readonly) NSDictionary *parameters NS_AVAILABLE_IOS(9_0)__TVOS_PROHIBITED;

// How the application should be activated in response to the action.
@property (nonatomic, assign, readonly) UIUserNotificationActivationMode activationMode __TVOS_PROHIBITED;

// Whether this action is secure and should require unlocking before being performed. If the activation mode is UIUserNotificationActivationModeForeground, then the action is considered secure and this property is ignored.
@property (nonatomic, assign, readonly, getter=isAuthenticationRequired) BOOL authenticationRequired __TVOS_PROHIBITED;

// Whether this action should be indicated as destructive when displayed.
@property (nonatomic, assign, readonly, getter=isDestructive) BOOL destructive __TVOS_PROHIBITED;

@end

NS_CLASS_DEPRECATED_IOS(8_0, 10_0, "Use UserNotifications Framework's UNNotificationAction") __TVOS_PROHIBITED
@interface UIMutableUserNotificationAction : UIUserNotificationAction

// The unique identifier for this action.
@property (nullable, nonatomic, copy) NSString *identifier;

// The localized title to display for this action.
@property (nullable, nonatomic, copy) NSString *title;

// The behavior of this action when the user activates it.
@property (nonatomic, assign) UIUserNotificationActionBehavior behavior NS_AVAILABLE_IOS(9_0);

// Parameters that can be used by some types of actions.
@property (nonatomic, copy) NSDictionary *parameters NS_AVAILABLE_IOS(9_0);

// How the application should be activated in response to the action.
@property (nonatomic, assign) UIUserNotificationActivationMode activationMode;

// Whether this action is secure and should require unlocking before being performed. If the activation mode is UIUserNotificationActivationModeForeground, then the action is considered secure and this property is ignored.
@property (nonatomic, assign, getter=isAuthenticationRequired) BOOL authenticationRequired;

// Whether this action should be indicated as destructive when displayed.
@property (nonatomic, assign, getter=isDestructive) BOOL destructive;

@end

NS_ASSUME_NONNULL_END
