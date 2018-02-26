//
//  UIApplicationShortcutItem.h
//  UIKit
//
//  Copyright © 2015-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class UIImage;

typedef NS_ENUM(NSInteger, UIApplicationShortcutIconType) {
    UIApplicationShortcutIconTypeCompose,
    UIApplicationShortcutIconTypePlay,
    UIApplicationShortcutIconTypePause,
    UIApplicationShortcutIconTypeAdd,
    UIApplicationShortcutIconTypeLocation,
    UIApplicationShortcutIconTypeSearch,
    UIApplicationShortcutIconTypeShare,
    UIApplicationShortcutIconTypeProhibit       NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeContact        NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeHome           NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeMarkLocation   NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeFavorite       NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeLove           NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeCloud          NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeInvitation     NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeConfirmation   NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeMail           NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeMessage        NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeDate           NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeTime           NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeCapturePhoto   NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeCaptureVideo   NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeTask           NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeTaskCompleted  NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeAlarm          NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeBookmark       NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeShuffle        NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeAudio          NS_ENUM_AVAILABLE_IOS(9_1),
    UIApplicationShortcutIconTypeUpdate         NS_ENUM_AVAILABLE_IOS(9_1)
} NS_ENUM_AVAILABLE_IOS(9_0) __TVOS_PROHIBITED;

NS_CLASS_AVAILABLE_IOS(9_0) __TVOS_PROHIBITED
@interface UIApplicationShortcutIcon : NSObject <NSCopying>

// Create an icon using a system-defined image.
+ (instancetype)iconWithType:(UIApplicationShortcutIconType)type;

// Create an icon from a custom image.
// The provided image named will be loaded from the app's bundle
// and will be masked to conform to the system-defined icon style.
+ (instancetype)iconWithTemplateImageName:(NSString *)templateImageName;

@end

NS_CLASS_AVAILABLE_IOS(9_0) __TVOS_PROHIBITED
@interface UIApplicationShortcutItem : NSObject <NSCopying, NSMutableCopying>

- (instancetype)init NS_UNAVAILABLE;
- (instancetype)initWithType:(NSString *)type localizedTitle:(NSString *)localizedTitle localizedSubtitle:(nullable NSString *)localizedSubtitle icon:(nullable UIApplicationShortcutIcon *)icon userInfo:(nullable NSDictionary *)userInfo NS_DESIGNATED_INITIALIZER;
- (instancetype)initWithType:(NSString *)type localizedTitle:(NSString *)localizedTitle;

// An application-specific string that identifies the type of action to perform.
@property (nonatomic, copy, readonly) NSString *type;

// Properties controlling how the item should be displayed on the home screen.
@property (nonatomic, copy, readonly) NSString *localizedTitle;
@property (nullable, nonatomic, copy, readonly) NSString *localizedSubtitle;
@property (nullable, nonatomic, copy, readonly) UIApplicationShortcutIcon *icon;

// Application-specific information needed to perform the action.
// Will throw an exception if the NSDictionary is not plist-encodable.
@property (nullable, nonatomic, copy, readonly) NSDictionary<NSString *, id <NSSecureCoding>> *userInfo;

@end

NS_CLASS_AVAILABLE_IOS(9_0) __TVOS_PROHIBITED
@interface UIMutableApplicationShortcutItem : UIApplicationShortcutItem

// An application-specific string that identifies the type of action to perform.
@property (nonatomic, copy) NSString *type;

// Properties controlling how the item should be displayed on the home screen.
@property (nonatomic, copy) NSString *localizedTitle;
@property (nullable, nonatomic, copy) NSString *localizedSubtitle;
@property (nullable, nonatomic, copy) UIApplicationShortcutIcon *icon;

// Application-specific information needed to perform the action.
// Will throw an exception if the NSDictionary is not plist-encodable.
@property (nullable, nonatomic, copy) NSDictionary<NSString *, id <NSSecureCoding>> *userInfo;

@end

NS_ASSUME_NONNULL_END
