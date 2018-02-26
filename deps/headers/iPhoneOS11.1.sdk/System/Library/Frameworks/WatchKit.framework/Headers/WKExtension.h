//
//  WKExtension.h
//  WatchKit
//
//  Copyright (c) 2015 Apple Inc. All rights reserved.
//

#if TARGET_OS_WATCH

#import <WatchKit/WKDefines.h>

NS_ASSUME_NONNULL_BEGIN

@protocol WKExtensionDelegate;
@class HKWorkoutConfiguration;
@class UNNotification;
@class UILocalNotification;
@class WKRefreshBackgroundTask;

WK_AVAILABLE_WATCHOS_ONLY(2.0)
@interface WKExtension : NSObject

+ (WKExtension *)sharedExtension;

- (void)openSystemURL:(NSURL *)url;

@property (nonatomic, weak, nullable) id<WKExtensionDelegate> delegate;
@property (nonatomic, readonly, nullable) WKInterfaceController *rootInterfaceController;
@property (nonatomic, readonly, nullable) WKInterfaceController *visibleInterfaceController WK_AVAILABLE_WATCHOS_ONLY(4.0); // in the cases when queried after an app launch we will return the instance of the last visible interface controller

typedef NS_ENUM(NSInteger, WKApplicationState) {
    WKApplicationStateActive,
    WKApplicationStateInactive,
    WKApplicationStateBackground,
} WK_AVAILABLE_WATCHOS_ONLY(3.0);
@property (nonatomic, readonly) WKApplicationState applicationState WK_AVAILABLE_WATCHOS_ONLY(3.0);
@property (nonatomic, readonly) BOOL isApplicationRunningInDock WK_AVAILABLE_WATCHOS_ONLY(4.0);
@property (nonatomic, getter=isAutorotating) BOOL autorotating WK_AVAILABLE_WATCHOS_ONLY(4.0);	  // default is NO

// when frontmostTimeoutExtended is YES, default time for "ON SCREEN WAKE SHOW LAST APP" setting of 2 minutes will be extended to 8 minutes for this app
@property (nonatomic, getter=isFrontmostTimeoutExtended) BOOL frontmostTimeoutExtended WK_AVAILABLE_WATCHOS_ONLY(4.0);

// Only an application which is in an active workout or location session and is foreground is allowed to enable water lock
- (void)enableWaterLock WK_AVAILABLE_WATCHOS_ONLY(4.0);

@end

WK_AVAILABLE_WATCHOS_ONLY(2.0)
@protocol WKExtensionDelegate <NSObject>

@optional

- (void)applicationDidFinishLaunching;
- (void)applicationDidBecomeActive;
- (void)applicationWillResignActive;
- (void)applicationWillEnterForeground;
- (void)applicationDidEnterBackground;

// iOS app started a workout. -[HKHealthStore startWorkoutSession:] should be called from here
- (void)handleWorkoutConfiguration:(HKWorkoutConfiguration *)workoutConfiguration WK_AVAILABLE_WATCHOS_ONLY(3.0);

- (void)handleUserActivity:(nullable NSDictionary *)userInfo;
- (void)handleActivity:(NSUserActivity *)userActivity WK_AVAILABLE_WATCHOS_ONLY(3.2);

- (void)handleBackgroundTasks:(NSSet <WKRefreshBackgroundTask *> *)backgroundTasks WK_AVAILABLE_WATCHOS_ONLY(3.0);

- (void)deviceOrientationDidChange WK_AVAILABLE_WATCHOS_ONLY(4.0); // called when WKInterfaceDeviceWristLocation or WKInterfaceDeviceCrownOrientation changes

// deprecated
- (void)handleActionWithIdentifier:(nullable NSString *)identifier forRemoteNotification:(NSDictionary *)remoteNotification WK_DEPRECATED_WATCHOS(2.0, 3.0, "use UNUserNotificationCenterDelegate");
- (void)handleActionWithIdentifier:(nullable NSString *)identifier forLocalNotification:(UILocalNotification *)localNotification WK_DEPRECATED_WATCHOS(2.0, 3.0, "use UNUserNotificationCenterDelegate");
- (void)handleActionWithIdentifier:(nullable NSString *)identifier forRemoteNotification:(NSDictionary *)remoteNotification withResponseInfo:(NSDictionary *)responseInfo WK_DEPRECATED_WATCHOS(2.0, 3.0, "use UNUserNotificationCenterDelegate");
- (void)handleActionWithIdentifier:(nullable NSString *)identifier forLocalNotification:(UILocalNotification *)localNotification withResponseInfo:(NSDictionary *)responseInfo WK_DEPRECATED_WATCHOS(2.0, 3.0, "use UNUserNotificationCenterDelegate");
- (void)didReceiveRemoteNotification:(NSDictionary *)userInfo WK_DEPRECATED_WATCHOS(2.0, 3.0, "use UNUserNotificationCenterDelegate");
- (void)didReceiveLocalNotification:(UILocalNotification *)notification WK_DEPRECATED_WATCHOS(2.0, 3.0, "use UNUserNotificationCenterDelegate");

@end

NS_ASSUME_NONNULL_END

#endif // TARGET_OS_WATCH
