//
//  UNNotificationSound.h
//  UserNotifications
//
//  Copyright © 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

__IOS_AVAILABLE(10.0) __WATCHOS_AVAILABLE(3.0) __TVOS_PROHIBITED
@interface UNNotificationSound : NSObject <NSCopying, NSSecureCoding>

// The default sound used for notifications.
+ (instancetype)defaultSound;

// The name of a sound file to be played for the notification. The sound file must be contained in the app’s bundle or in the Library/Sounds folder of the app's data container. If files exist in both locations then the file in the app's data container will be preferred.
+ (instancetype)soundNamed:(NSString *)name __WATCHOS_PROHIBITED;

- (instancetype)init NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
