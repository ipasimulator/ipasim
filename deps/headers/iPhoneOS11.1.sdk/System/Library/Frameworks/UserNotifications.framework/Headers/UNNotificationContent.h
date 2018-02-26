//
//  UNNotificationContent.h
//  UserNotifications
//
//  Copyright © 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@class UNNotificationAttachment;
@class UNNotificationSound;

NS_ASSUME_NONNULL_BEGIN

__IOS_AVAILABLE(10.0) __TVOS_AVAILABLE(10.0) __WATCHOS_AVAILABLE(3.0)
@interface UNNotificationContent : NSObject <NSCopying, NSMutableCopying, NSSecureCoding>

// Optional array of attachments.
@property (NS_NONATOMIC_IOSONLY, readonly, copy) NSArray <UNNotificationAttachment *> *attachments __TVOS_PROHIBITED;

// The application badge number.
@property (NS_NONATOMIC_IOSONLY, readonly, copy, nullable) NSNumber *badge;

// The body of the notification.
@property (NS_NONATOMIC_IOSONLY, readonly, copy) NSString *body __TVOS_PROHIBITED;

// The identifier for a registered UNNotificationCategory that will be used to determine the appropriate actions to display for the notification.
@property (NS_NONATOMIC_IOSONLY, readonly, copy) NSString *categoryIdentifier __TVOS_PROHIBITED;

// The launch image that will be used when the app is opened from the notification.
@property (NS_NONATOMIC_IOSONLY, readonly, copy) NSString *launchImageName __TVOS_PROHIBITED;

// The sound that will be played for the notification.
@property (NS_NONATOMIC_IOSONLY, readonly, copy, nullable) UNNotificationSound *sound __TVOS_PROHIBITED;

// The subtitle of the notification.
@property (NS_NONATOMIC_IOSONLY, readonly, copy) NSString *subtitle __TVOS_PROHIBITED;

// The unique identifier for the thread or conversation related to this notification request. It will be used to visually group notifications together.
@property (NS_NONATOMIC_IOSONLY, readonly, copy) NSString *threadIdentifier __TVOS_PROHIBITED;

// The title of the notification.
@property (NS_NONATOMIC_IOSONLY, readonly, copy) NSString *title __TVOS_PROHIBITED;

// Apps can set the userInfo for locally scheduled notification requests. The contents of the push payload will be set as the userInfo for remote notifications.
@property (NS_NONATOMIC_IOSONLY, readonly, copy) NSDictionary *userInfo __TVOS_PROHIBITED;

@end

__IOS_AVAILABLE(10.0) __TVOS_AVAILABLE(10.0) __WATCHOS_AVAILABLE(3.0)
@interface UNMutableNotificationContent : UNNotificationContent

// Optional array of attachments.
@property (NS_NONATOMIC_IOSONLY, copy) NSArray <UNNotificationAttachment *> *attachments __TVOS_PROHIBITED;

// The application badge number. nil means no change. 0 to hide.
@property (NS_NONATOMIC_IOSONLY, copy, nullable) NSNumber *badge;

// The body of the notification. Use -[NSString localizedUserNotificationStringForKey:arguments:] to provide a string that will be localized at the time that the notification is presented.
@property (NS_NONATOMIC_IOSONLY, copy) NSString *body __TVOS_PROHIBITED;

// The identifier for a registered UNNotificationCategory that will be used to determine the appropriate actions to display for the notification.
@property (NS_NONATOMIC_IOSONLY, copy) NSString *categoryIdentifier __TVOS_PROHIBITED;

// The launch image that will be used when the app is opened from the notification.
@property (NS_NONATOMIC_IOSONLY, copy) NSString *launchImageName __TVOS_PROHIBITED;

// The sound that will be played for the notification.
@property (NS_NONATOMIC_IOSONLY, copy, nullable) UNNotificationSound *sound __TVOS_PROHIBITED;

// The subtitle of the notification. Use -[NSString localizedUserNotificationStringForKey:arguments:] to provide a string that will be localized at the time that the notification is presented.
@property (NS_NONATOMIC_IOSONLY, copy) NSString *subtitle __TVOS_PROHIBITED;

// The unique identifier for the thread or conversation related to this notification request. It will be used to visually group notifications together.
@property (NS_NONATOMIC_IOSONLY, copy) NSString *threadIdentifier __TVOS_PROHIBITED;

// The title of the notification. Use -[NSString localizedUserNotificationStringForKey:arguments:] to provide a string that will be localized at the time that the notification is presented.
@property (NS_NONATOMIC_IOSONLY, copy) NSString *title __TVOS_PROHIBITED;

// Apps can set the userInfo for locally scheduled notification requests. The contents of the push payload will be set as the userInfo for remote notifications.
@property (NS_NONATOMIC_IOSONLY, copy) NSDictionary *userInfo;

@end

NS_ASSUME_NONNULL_END
