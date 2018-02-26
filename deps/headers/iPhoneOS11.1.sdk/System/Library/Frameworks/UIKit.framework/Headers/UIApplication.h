//
//  UIApplication.h
//  UIKit
//
//  Copyright (c) 2005-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UIKit/UIKitDefines.h>
#import <UIKit/UIResponder.h>
#import <UIKit/UIInterface.h>
#import <UIKit/UIDevice.h>
#import <UIKit/UIAlert.h>
#import <UIKit/UIContentSizeCategory.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, UIStatusBarStyle) {
    UIStatusBarStyleDefault                                     = 0, // Dark content, for use on light backgrounds
    UIStatusBarStyleLightContent     NS_ENUM_AVAILABLE_IOS(7_0) = 1, // Light content, for use on dark backgrounds
    
    UIStatusBarStyleBlackTranslucent NS_ENUM_DEPRECATED_IOS(2_0, 7_0, "Use UIStatusBarStyleLightContent") = 1,
    UIStatusBarStyleBlackOpaque      NS_ENUM_DEPRECATED_IOS(2_0, 7_0, "Use UIStatusBarStyleLightContent") = 2,
} __TVOS_PROHIBITED;

typedef NS_ENUM(NSInteger, UIStatusBarAnimation) {
    UIStatusBarAnimationNone,
    UIStatusBarAnimationFade NS_ENUM_AVAILABLE_IOS(3_2),
    UIStatusBarAnimationSlide NS_ENUM_AVAILABLE_IOS(3_2),
} __TVOS_PROHIBITED;

// Note that UIInterfaceOrientationLandscapeLeft is equal to UIDeviceOrientationLandscapeRight (and vice versa).
// This is because rotating the device to the left requires rotating the content to the right.
typedef NS_ENUM(NSInteger, UIInterfaceOrientation) {
    UIInterfaceOrientationUnknown            = UIDeviceOrientationUnknown,
    UIInterfaceOrientationPortrait           = UIDeviceOrientationPortrait,
    UIInterfaceOrientationPortraitUpsideDown = UIDeviceOrientationPortraitUpsideDown,
    UIInterfaceOrientationLandscapeLeft      = UIDeviceOrientationLandscapeRight,
    UIInterfaceOrientationLandscapeRight     = UIDeviceOrientationLandscapeLeft
} __TVOS_PROHIBITED;

/* This exception is raised if supportedInterfaceOrientations returns 0, or if preferredInterfaceOrientationForPresentation
   returns an orientation that is not supported.
*/
UIKIT_EXTERN NSExceptionName const UIApplicationInvalidInterfaceOrientationException NS_AVAILABLE_IOS(6_0) __TVOS_PROHIBITED;

typedef NS_OPTIONS(NSUInteger, UIInterfaceOrientationMask) {
    UIInterfaceOrientationMaskPortrait = (1 << UIInterfaceOrientationPortrait),
    UIInterfaceOrientationMaskLandscapeLeft = (1 << UIInterfaceOrientationLandscapeLeft),
    UIInterfaceOrientationMaskLandscapeRight = (1 << UIInterfaceOrientationLandscapeRight),
    UIInterfaceOrientationMaskPortraitUpsideDown = (1 << UIInterfaceOrientationPortraitUpsideDown),
    UIInterfaceOrientationMaskLandscape = (UIInterfaceOrientationMaskLandscapeLeft | UIInterfaceOrientationMaskLandscapeRight),
    UIInterfaceOrientationMaskAll = (UIInterfaceOrientationMaskPortrait | UIInterfaceOrientationMaskLandscapeLeft | UIInterfaceOrientationMaskLandscapeRight | UIInterfaceOrientationMaskPortraitUpsideDown),
    UIInterfaceOrientationMaskAllButUpsideDown = (UIInterfaceOrientationMaskPortrait | UIInterfaceOrientationMaskLandscapeLeft | UIInterfaceOrientationMaskLandscapeRight),
} __TVOS_PROHIBITED;

#define UIDeviceOrientationIsValidInterfaceOrientation(orientation) ((UIDeviceOrientation)(orientation) == UIDeviceOrientationPortrait || (UIDeviceOrientation)(orientation) == UIDeviceOrientationPortraitUpsideDown || (UIDeviceOrientation)(orientation) == UIDeviceOrientationLandscapeLeft || (UIDeviceOrientation)(orientation) == UIDeviceOrientationLandscapeRight)

static inline BOOL UIInterfaceOrientationIsPortrait(UIInterfaceOrientation orientation) __TVOS_PROHIBITED {
    return ((orientation) == UIInterfaceOrientationPortrait || (orientation) == UIInterfaceOrientationPortraitUpsideDown);
}

static inline BOOL UIInterfaceOrientationIsLandscape(UIInterfaceOrientation orientation) __TVOS_PROHIBITED {
    return ((orientation) == UIInterfaceOrientationLandscapeLeft || (orientation) == UIInterfaceOrientationLandscapeRight);
}

typedef NS_OPTIONS(NSUInteger, UIRemoteNotificationType) {
    UIRemoteNotificationTypeNone    = 0,
    UIRemoteNotificationTypeBadge   = 1 << 0,
    UIRemoteNotificationTypeSound   = 1 << 1,
    UIRemoteNotificationTypeAlert   = 1 << 2,
    UIRemoteNotificationTypeNewsstandContentAvailability = 1 << 3,
} NS_ENUM_DEPRECATED_IOS(3_0, 8_0, "Use UserNotifications Framework's UNAuthorizationOptions for user notifications and registerForRemoteNotifications for receiving remote notifications instead.") __TVOS_PROHIBITED;

typedef NS_ENUM(NSUInteger, UIBackgroundFetchResult) {
    UIBackgroundFetchResultNewData,
    UIBackgroundFetchResultNoData,
    UIBackgroundFetchResultFailed
} NS_ENUM_AVAILABLE_IOS(7_0);

typedef NS_ENUM(NSInteger, UIBackgroundRefreshStatus) {
    UIBackgroundRefreshStatusRestricted, //< unavailable on this system due to device configuration; the user cannot enable the feature
    UIBackgroundRefreshStatusDenied,     //< explicitly disabled by the user for this application
    UIBackgroundRefreshStatusAvailable   //< enabled for this application
} API_AVAILABLE(ios(7.0), tvos(11.0));
    
typedef NS_ENUM(NSInteger, UIApplicationState) {
    UIApplicationStateActive,
    UIApplicationStateInactive,
    UIApplicationStateBackground
} NS_ENUM_AVAILABLE_IOS(4_0);

typedef NSUInteger UIBackgroundTaskIdentifier;
UIKIT_EXTERN const UIBackgroundTaskIdentifier UIBackgroundTaskInvalid  NS_AVAILABLE_IOS(4_0);
UIKIT_EXTERN const NSTimeInterval UIMinimumKeepAliveTimeout  NS_AVAILABLE_IOS(4_0);
UIKIT_EXTERN const NSTimeInterval UIApplicationBackgroundFetchIntervalMinimum API_AVAILABLE(ios(7.0), tvos(11.0));
UIKIT_EXTERN const NSTimeInterval UIApplicationBackgroundFetchIntervalNever API_AVAILABLE(ios(7.0), tvos(11.0));

@class CKShareMetadata;
@class UIView, UIWindow;
@class UIStatusBar, UIStatusBarWindow, UILocalNotification;
@protocol UIApplicationDelegate;
@class INIntent;
@class INIntentResponse;

NS_CLASS_AVAILABLE_IOS(2_0) @interface UIApplication : UIResponder

#if UIKIT_DEFINE_AS_PROPERTIES
@property(class, nonatomic, readonly) UIApplication *sharedApplication NS_EXTENSION_UNAVAILABLE_IOS("Use view controller based solutions where appropriate instead.");
#else
+ (UIApplication *)sharedApplication NS_EXTENSION_UNAVAILABLE_IOS("Use view controller based solutions where appropriate instead.");
#endif

@property(nullable, nonatomic, assign) id<UIApplicationDelegate> delegate;

- (void)beginIgnoringInteractionEvents NS_EXTENSION_UNAVAILABLE_IOS("");               // nested. set should be set during animations & transitions to ignore touch and other events
- (void)endIgnoringInteractionEvents NS_EXTENSION_UNAVAILABLE_IOS("");
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly, getter=isIgnoringInteractionEvents) BOOL ignoringInteractionEvents;                  // returns YES if we are at least one deep in ignoring events
#else
- (BOOL)isIgnoringInteractionEvents;                  // returns YES if we are at least one deep in ignoring events
#endif

@property(nonatomic,getter=isIdleTimerDisabled)       BOOL idleTimerDisabled;	  // default is NO

- (BOOL)openURL:(NSURL*)url NS_DEPRECATED_IOS(2_0, 10_0, "Please use openURL:options:completionHandler: instead") NS_EXTENSION_UNAVAILABLE_IOS("");
- (BOOL)canOpenURL:(NSURL *)url NS_AVAILABLE_IOS(3_0);

// Options are specified in the section below for openURL options. An empty options dictionary will result in the same
// behavior as the older openURL call, aside from the fact that this is asynchronous and calls the completion handler rather
// than returning a result.
// The completion handler is called on the main queue.
- (void)openURL:(NSURL*)url options:(NSDictionary<NSString *, id> *)options completionHandler:(void (^ __nullable)(BOOL success))completion NS_AVAILABLE_IOS(10_0) NS_EXTENSION_UNAVAILABLE_IOS("");

- (void)sendEvent:(UIEvent *)event;

@property(nullable, nonatomic,readonly) UIWindow *keyWindow;
@property(nonatomic,readonly) NSArray<__kindof UIWindow *>  *windows;

- (BOOL)sendAction:(SEL)action to:(nullable id)target from:(nullable id)sender forEvent:(nullable UIEvent *)event;

@property(nonatomic,getter=isNetworkActivityIndicatorVisible) BOOL networkActivityIndicatorVisible __TVOS_PROHIBITED; // showing network spinning gear in status bar. default is NO

@property(readonly, nonatomic) UIStatusBarStyle statusBarStyle __TVOS_PROHIBITED; // default is UIStatusBarStyleDefault

@property(readonly, nonatomic,getter=isStatusBarHidden) BOOL statusBarHidden __TVOS_PROHIBITED;

@property(readonly, nonatomic) UIInterfaceOrientation statusBarOrientation __TVOS_PROHIBITED;

// The system only calls this method if the application delegate has not
// implemented the delegate equivalent. It returns the orientations specified by
// the application's info.plist. If no supported interface orientations were
// specified it will return UIInterfaceOrientationMaskAll on an iPad and
// UIInterfaceOrientationMaskAllButUpsideDown on a phone.  The return value
// should be one of the UIInterfaceOrientationMask values which indicates the
// orientations supported by this application.
- (UIInterfaceOrientationMask)supportedInterfaceOrientationsForWindow:(nullable UIWindow *)window NS_AVAILABLE_IOS(6_0) __TVOS_PROHIBITED;

@property(nonatomic,readonly) NSTimeInterval statusBarOrientationAnimationDuration __TVOS_PROHIBITED; // Returns the animation duration for the status bar during a 90 degree orientation change.  It should be doubled for a 180 degree orientation change.
@property(nonatomic,readonly) CGRect statusBarFrame __TVOS_PROHIBITED; // returns CGRectZero if the status bar is hidden

@property(nonatomic) NSInteger applicationIconBadgeNumber;  // set to 0 to hide. default is 0. In iOS 8.0 and later, your application must register for user notifications using -[UIApplication registerUserNotificationSettings:] before being able to set the icon badge.

@property(nonatomic) BOOL applicationSupportsShakeToEdit NS_AVAILABLE_IOS(3_0) __TVOS_PROHIBITED;

@property(nonatomic,readonly) UIApplicationState applicationState NS_AVAILABLE_IOS(4_0);
@property(nonatomic,readonly) NSTimeInterval backgroundTimeRemaining NS_AVAILABLE_IOS(4_0);

- (UIBackgroundTaskIdentifier)beginBackgroundTaskWithExpirationHandler:(void(^ __nullable)(void))handler  NS_AVAILABLE_IOS(4_0) NS_REQUIRES_SUPER;
- (UIBackgroundTaskIdentifier)beginBackgroundTaskWithName:(nullable NSString *)taskName expirationHandler:(void(^ __nullable)(void))handler NS_AVAILABLE_IOS(7_0) NS_REQUIRES_SUPER;
- (void)endBackgroundTask:(UIBackgroundTaskIdentifier)identifier NS_AVAILABLE_IOS(4_0) NS_REQUIRES_SUPER;

/*! The system guarantees that it will not wake up your application for a background fetch more
    frequently than the interval provided. Set to UIApplicationBackgroundFetchIntervalMinimum to be
    woken as frequently as the system desires, or to UIApplicationBackgroundFetchIntervalNever (the
    default) to never be woken for a background fetch.
 
    This setter will have no effect unless your application has the "fetch" 
    UIBackgroundMode. See the UIApplicationDelegate method
    `application:performFetchWithCompletionHandler:` for more. */
- (void)setMinimumBackgroundFetchInterval:(NSTimeInterval)minimumBackgroundFetchInterval API_AVAILABLE(ios(7.0), tvos(11.0));

/*! When background refresh is available for an application, it may launched or resumed in the background to handle significant
    location changes, remote notifications, background fetches, etc. Observe UIApplicationBackgroundRefreshStatusDidChangeNotification to
    be notified of changes. */
@property (nonatomic, readonly) UIBackgroundRefreshStatus backgroundRefreshStatus API_AVAILABLE(ios(7.0), tvos(11.0));

@property(nonatomic,readonly,getter=isProtectedDataAvailable) BOOL protectedDataAvailable NS_AVAILABLE_IOS(4_0);

@property(nonatomic,readonly) UIUserInterfaceLayoutDirection userInterfaceLayoutDirection NS_AVAILABLE_IOS(5_0);

// Return the size category
@property(nonatomic,readonly) UIContentSizeCategory preferredContentSizeCategory NS_AVAILABLE_IOS(7_0);

@end

@interface UIApplication (UIRemoteNotifications)

// Calling this will result in either application:didRegisterForRemoteNotificationsWithDeviceToken: or application:didFailToRegisterForRemoteNotificationsWithError: to be called on the application delegate. Note: these callbacks will be made only if the application has successfully registered for user notifications with registerUserNotificationSettings:, or if it is enabled for Background App Refresh.
- (void)registerForRemoteNotifications NS_AVAILABLE_IOS(8_0);

- (void)unregisterForRemoteNotifications NS_AVAILABLE_IOS(3_0);

// Returns YES if the application is currently registered for remote notifications, taking into account any systemwide settings; doesn't relate to connectivity.
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly, getter=isRegisteredForRemoteNotifications) BOOL registeredForRemoteNotifications NS_AVAILABLE_IOS(8_0);
#else
- (BOOL)isRegisteredForRemoteNotifications NS_AVAILABLE_IOS(8_0);
#endif

- (void)registerForRemoteNotificationTypes:(UIRemoteNotificationType)types NS_DEPRECATED_IOS(3_0, 8_0, "Use -[UIApplication registerForRemoteNotifications] and UserNotifications Framework's -[UNUserNotificationCenter requestAuthorizationWithOptions:completionHandler:]") __TVOS_PROHIBITED;

// Returns the enabled types, also taking into account any systemwide settings; doesn't relate to connectivity.
- (UIRemoteNotificationType)enabledRemoteNotificationTypes NS_DEPRECATED_IOS(3_0, 8_0, "Use -[UIApplication isRegisteredForRemoteNotifications] and UserNotifications Framework's -[UNUserNotificationCenter getNotificationSettingsWithCompletionHandler:] to retrieve user-enabled remote notification and user notification settings") __TVOS_PROHIBITED;

@end

// In iOS 8.0 and later, your application must register for user notifications using -[UIApplication registerUserNotificationSettings:] before being able to schedule and present UILocalNotifications
@interface UIApplication (UILocalNotifications)

- (void)presentLocalNotificationNow:(UILocalNotification *)notification NS_DEPRECATED_IOS(4_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenter addNotificationRequest:withCompletionHandler:]") __TVOS_PROHIBITED;

- (void)scheduleLocalNotification:(UILocalNotification *)notification NS_DEPRECATED_IOS(4_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenter addNotificationRequest:withCompletionHandler:]") __TVOS_PROHIBITED;  // copies notification
- (void)cancelLocalNotification:(UILocalNotification *)notification NS_DEPRECATED_IOS(4_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenter removePendingNotificationRequestsWithIdentifiers:]") __TVOS_PROHIBITED;
- (void)cancelAllLocalNotifications NS_DEPRECATED_IOS(4_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenter removeAllPendingNotificationRequests]") __TVOS_PROHIBITED;

@property(nullable,nonatomic,copy) NSArray<UILocalNotification *> *scheduledLocalNotifications NS_DEPRECATED_IOS(4_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenter getPendingNotificationRequestsWithCompletionHandler:]") __TVOS_PROHIBITED;

@end

@class UIUserNotificationSettings;
@interface UIApplication (UIUserNotificationSettings)

// Registering UIUserNotificationSettings more than once results in previous settings being overwritten.
- (void)registerUserNotificationSettings:(UIUserNotificationSettings *)notificationSettings NS_DEPRECATED_IOS(8_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenter requestAuthorizationWithOptions:completionHandler:] and -[UNUserNotificationCenter setNotificationCategories:]") __TVOS_PROHIBITED;

// Returns the enabled user notification settings, also taking into account any systemwide settings.
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly, nullable) UIUserNotificationSettings *currentUserNotificationSettings NS_DEPRECATED_IOS(8_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenter getNotificationSettingsWithCompletionHandler:] and -[UNUserNotificationCenter getNotificationCategoriesWithCompletionHandler:]") __TVOS_PROHIBITED;
#else
- (nullable UIUserNotificationSettings *)currentUserNotificationSettings NS_DEPRECATED_IOS(8_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenter getNotificationSettingsWithCompletionHandler:] and -[UNUserNotificationCenter getNotificationCategoriesWithCompletionHandler:]") __TVOS_PROHIBITED;
#endif

@end

@interface UIApplication (UIRemoteControlEvents)

- (void)beginReceivingRemoteControlEvents NS_AVAILABLE_IOS(4_0);
- (void)endReceivingRemoteControlEvents NS_AVAILABLE_IOS(4_0);

@end

@interface UIApplication (UINewsstand)
- (void)setNewsstandIconImage:(nullable UIImage *)image NS_DEPRECATED_IOS(5_0, 9_0, "Newsstand apps now behave like normal apps on SpringBoard") __TVOS_PROHIBITED;
@end

@class UIApplicationShortcutItem;
@interface UIApplication (UIShortcutItems)
// Register shortcuts to display on the home screen, or retrieve currently registered shortcuts.
@property (nullable, nonatomic, copy) NSArray<UIApplicationShortcutItem *> *shortcutItems NS_AVAILABLE_IOS(9_0) __TVOS_PROHIBITED;
@end

@interface UIApplication (UIAlternateApplicationIcons)
// If false, alternate icons are not supported for the current process.
@property (readonly, nonatomic) BOOL supportsAlternateIcons NS_EXTENSION_UNAVAILABLE("Extensions may not have alternate icons") API_AVAILABLE(ios(10.3), tvos(10.2));

// Pass `nil` to use the primary application icon. The completion handler will be invoked asynchronously on an arbitrary background queue; be sure to dispatch back to the main queue before doing any further UI work.
- (void)setAlternateIconName:(nullable NSString *)alternateIconName completionHandler:(nullable void (^)(NSError *_Nullable error))completionHandler NS_EXTENSION_UNAVAILABLE("Extensions may not have alternate icons") API_AVAILABLE(ios(10.3), tvos(10.2));

// If `nil`, the primary application icon is being used.
@property (nullable, readonly, nonatomic) NSString *alternateIconName NS_EXTENSION_UNAVAILABLE("Extensions may not have alternate icons") API_AVAILABLE(ios(10.3), tvos(10.2));
@end

@protocol UIStateRestoring;
@interface UIApplication (UIStateRestoration)
// These methods are used to inform the system that state restoration is occuring asynchronously after the application
// has processed its restoration archive on launch. In the even of a crash, the system will be able to detect that it may
// have been caused by a bad restoration archive and arrange to ignore it on a subsequent application launch.
- (void)extendStateRestoration  NS_AVAILABLE_IOS(6_0);
- (void)completeStateRestoration  NS_AVAILABLE_IOS(6_0);

// Indicate the application should not use the snapshot on next launch, even if there is a valid state restoration archive.
// This should only be called from methods invoked from State Preservation, else it is ignored.
- (void)ignoreSnapshotOnNextApplicationLaunch NS_AVAILABLE_IOS(7_0);

// Register non-View/ViewController objects for state restoration so other objects can reference them within state restoration archives.
// If the object implements encode/decode, those methods will be called during save/restore.
// Obj and identifier must not be nil, or will raise UIRestorationObjectRegistrationException.
// Objects do not need to be unregistered when they are deleted, the State Restoration system will notice and stop tracking the object.
+ (void)registerObjectForStateRestoration:(id<UIStateRestoring>)object restorationIdentifier:(NSString *)restorationIdentifier NS_AVAILABLE_IOS(7_0);
@end


#if UIKIT_STRING_ENUMS
typedef NSString * UIApplicationLaunchOptionsKey NS_EXTENSIBLE_STRING_ENUM;
#else
typedef NSString * UIApplicationLaunchOptionsKey;
#endif

@protocol UIApplicationDelegate<NSObject>

@optional

- (void)applicationDidFinishLaunching:(UIApplication *)application;
#if UIKIT_STRING_ENUMS
- (BOOL)application:(UIApplication *)application willFinishLaunchingWithOptions:(nullable NSDictionary<UIApplicationLaunchOptionsKey, id> *)launchOptions NS_AVAILABLE_IOS(6_0);
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(nullable NSDictionary<UIApplicationLaunchOptionsKey, id> *)launchOptions NS_AVAILABLE_IOS(3_0);
#else
- (BOOL)application:(UIApplication *)application willFinishLaunchingWithOptions:(nullable NSDictionary *)launchOptions NS_AVAILABLE_IOS(6_0);
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(nullable NSDictionary *)launchOptions NS_AVAILABLE_IOS(3_0);
#endif

- (void)applicationDidBecomeActive:(UIApplication *)application;
- (void)applicationWillResignActive:(UIApplication *)application;
- (BOOL)application:(UIApplication *)application handleOpenURL:(NSURL *)url NS_DEPRECATED_IOS(2_0, 9_0, "Please use application:openURL:options:") __TVOS_PROHIBITED;
- (BOOL)application:(UIApplication *)application openURL:(NSURL *)url sourceApplication:(nullable NSString *)sourceApplication annotation:(id)annotation NS_DEPRECATED_IOS(4_2, 9_0, "Please use application:openURL:options:") __TVOS_PROHIBITED;


#if UIKIT_STRING_ENUMS
typedef NSString * UIApplicationOpenURLOptionsKey NS_EXTENSIBLE_STRING_ENUM;
#else
typedef NSString * UIApplicationOpenURLOptionsKey;
#endif

- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenURLOptionsKey, id> *)options NS_AVAILABLE_IOS(9_0); // no equiv. notification. return NO if the application can't open for some reason

- (void)applicationDidReceiveMemoryWarning:(UIApplication *)application;      // try to clean up as much memory as possible. next step is to terminate app
- (void)applicationWillTerminate:(UIApplication *)application;
- (void)applicationSignificantTimeChange:(UIApplication *)application;        // midnight, carrier time update, daylight savings time change

- (void)application:(UIApplication *)application willChangeStatusBarOrientation:(UIInterfaceOrientation)newStatusBarOrientation duration:(NSTimeInterval)duration __TVOS_PROHIBITED;
- (void)application:(UIApplication *)application didChangeStatusBarOrientation:(UIInterfaceOrientation)oldStatusBarOrientation __TVOS_PROHIBITED;

- (void)application:(UIApplication *)application willChangeStatusBarFrame:(CGRect)newStatusBarFrame __TVOS_PROHIBITED;   // in screen coordinates
- (void)application:(UIApplication *)application didChangeStatusBarFrame:(CGRect)oldStatusBarFrame __TVOS_PROHIBITED;

// This callback will be made upon calling -[UIApplication registerUserNotificationSettings:]. The settings the user has granted to the application will be passed in as the second argument.
 - (void)application:(UIApplication *)application didRegisterUserNotificationSettings:(UIUserNotificationSettings *)notificationSettings NS_DEPRECATED_IOS(8_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenter requestAuthorizationWithOptions:completionHandler:]") __TVOS_PROHIBITED;

- (void)application:(UIApplication *)application didRegisterForRemoteNotificationsWithDeviceToken:(NSData *)deviceToken NS_AVAILABLE_IOS(3_0);

- (void)application:(UIApplication *)application didFailToRegisterForRemoteNotificationsWithError:(NSError *)error NS_AVAILABLE_IOS(3_0);

- (void)application:(UIApplication *)application didReceiveRemoteNotification:(NSDictionary *)userInfo NS_DEPRECATED_IOS(3_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenterDelegate willPresentNotification:withCompletionHandler:] or -[UNUserNotificationCenterDelegate didReceiveNotificationResponse:withCompletionHandler:] for user visible notifications and -[UIApplicationDelegate application:didReceiveRemoteNotification:fetchCompletionHandler:] for silent remote notifications");

- (void)application:(UIApplication *)application didReceiveLocalNotification:(UILocalNotification *)notification NS_DEPRECATED_IOS(4_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenterDelegate willPresentNotification:withCompletionHandler:] or -[UNUserNotificationCenterDelegate didReceiveNotificationResponse:withCompletionHandler:]") __TVOS_PROHIBITED;

// Called when your app has been activated by the user selecting an action from a local notification.
// A nil action identifier indicates the default action.
// You should call the completion handler as soon as you've finished handling the action.
- (void)application:(UIApplication *)application handleActionWithIdentifier:(nullable NSString *)identifier forLocalNotification:(UILocalNotification *)notification completionHandler:(void(^)())completionHandler NS_DEPRECATED_IOS(8_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenterDelegate didReceiveNotificationResponse:withCompletionHandler:]") __TVOS_PROHIBITED;

- (void)application:(UIApplication *)application handleActionWithIdentifier:(nullable NSString *)identifier forRemoteNotification:(NSDictionary *)userInfo withResponseInfo:(NSDictionary *)responseInfo completionHandler:(void(^)())completionHandler NS_DEPRECATED_IOS(9_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenterDelegate didReceiveNotificationResponse:withCompletionHandler:]") __TVOS_PROHIBITED;

// Called when your app has been activated by the user selecting an action from a remote notification.
// A nil action identifier indicates the default action.
// You should call the completion handler as soon as you've finished handling the action.
- (void)application:(UIApplication *)application handleActionWithIdentifier:(nullable NSString *)identifier forRemoteNotification:(NSDictionary *)userInfo completionHandler:(void(^)())completionHandler NS_DEPRECATED_IOS(8_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenterDelegate didReceiveNotificationResponse:withCompletionHandler:]") __TVOS_PROHIBITED;

- (void)application:(UIApplication *)application handleActionWithIdentifier:(nullable NSString *)identifier forLocalNotification:(UILocalNotification *)notification withResponseInfo:(NSDictionary *)responseInfo completionHandler:(void(^)())completionHandler NS_DEPRECATED_IOS(9_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenterDelegate didReceiveNotificationResponse:withCompletionHandler:]") __TVOS_PROHIBITED;

/*! This delegate method offers an opportunity for applications with the "remote-notification" background mode to fetch appropriate new data in response to an incoming remote notification. You should call the fetchCompletionHandler as soon as you're finished performing that operation, so the system can accurately estimate its power and data cost.
 
 This method will be invoked even if the application was launched or resumed because of the remote notification. The respective delegate methods will be invoked first. Note that this behavior is in contrast to application:didReceiveRemoteNotification:, which is not called in those cases, and which will not be invoked if this method is implemented. !*/
- (void)application:(UIApplication *)application didReceiveRemoteNotification:(NSDictionary *)userInfo fetchCompletionHandler:(void (^)(UIBackgroundFetchResult result))completionHandler NS_AVAILABLE_IOS(7_0);

/// Applications with the "fetch" background mode may be given opportunities to fetch updated content in the background or when it is convenient for the system. This method will be called in these situations. You should call the fetchCompletionHandler as soon as you're finished performing that operation, so the system can accurately estimate its power and data cost.
- (void)application:(UIApplication *)application performFetchWithCompletionHandler:(void (^)(UIBackgroundFetchResult result))completionHandler API_AVAILABLE(ios(7.0), tvos(11.0));

// Called when the user activates your application by selecting a shortcut on the home screen,
// except when -application:willFinishLaunchingWithOptions: or -application:didFinishLaunchingWithOptions returns NO.
- (void)application:(UIApplication *)application performActionForShortcutItem:(UIApplicationShortcutItem *)shortcutItem completionHandler:(void(^)(BOOL succeeded))completionHandler NS_AVAILABLE_IOS(9_0) __TVOS_PROHIBITED;

// Applications using an NSURLSession with a background configuration may be launched or resumed in the background in order to handle the
// completion of tasks in that session, or to handle authentication. This method will be called with the identifier of the session needing
// attention. Once a session has been created from a configuration object with that identifier, the session's delegate will begin receiving
// callbacks. If such a session has already been created (if the app is being resumed, for instance), then the delegate will start receiving
// callbacks without any action by the application. You should call the completionHandler as soon as you're finished handling the callbacks.
- (void)application:(UIApplication *)application handleEventsForBackgroundURLSession:(NSString *)identifier completionHandler:(void (^)(void))completionHandler NS_AVAILABLE_IOS(7_0);

- (void)application:(UIApplication *)application handleWatchKitExtensionRequest:(nullable NSDictionary *)userInfo reply:(void(^)(NSDictionary * __nullable replyInfo))reply NS_AVAILABLE_IOS(8_2);

- (void)applicationShouldRequestHealthAuthorization:(UIApplication *)application NS_AVAILABLE_IOS(9_0);

- (void)application:(UIApplication *)application handleIntent:(INIntent *)intent completionHandler:(void(^)(INIntentResponse *intentResponse))completionHandler NS_AVAILABLE_IOS(11_0);

- (void)applicationDidEnterBackground:(UIApplication *)application NS_AVAILABLE_IOS(4_0);
- (void)applicationWillEnterForeground:(UIApplication *)application NS_AVAILABLE_IOS(4_0);

- (void)applicationProtectedDataWillBecomeUnavailable:(UIApplication *)application NS_AVAILABLE_IOS(4_0);
- (void)applicationProtectedDataDidBecomeAvailable:(UIApplication *)application    NS_AVAILABLE_IOS(4_0);

@property (nullable, nonatomic, strong) UIWindow *window NS_AVAILABLE_IOS(5_0);

- (UIInterfaceOrientationMask)application:(UIApplication *)application supportedInterfaceOrientationsForWindow:(nullable UIWindow *)window  NS_AVAILABLE_IOS(6_0) __TVOS_PROHIBITED;

#if UIKIT_STRING_ENUMS
typedef NSString * UIApplicationExtensionPointIdentifier NS_EXTENSIBLE_STRING_ENUM;
#else
typedef NSString * UIApplicationExtensionPointIdentifier;
#endif

// Applications may reject specific types of extensions based on the extension point identifier.
// Constants representing common extension point identifiers are provided further down.
// If unimplemented, the default behavior is to allow the extension point identifier.
- (BOOL)application:(UIApplication *)application shouldAllowExtensionPointIdentifier:(UIApplicationExtensionPointIdentifier)extensionPointIdentifier NS_AVAILABLE_IOS(8_0);

#pragma mark -- State Restoration protocol adopted by UIApplication delegate --

- (nullable UIViewController *) application:(UIApplication *)application viewControllerWithRestorationIdentifierPath:(NSArray *)identifierComponents coder:(NSCoder *)coder NS_AVAILABLE_IOS(6_0);
- (BOOL) application:(UIApplication *)application shouldSaveApplicationState:(NSCoder *)coder NS_AVAILABLE_IOS(6_0);
- (BOOL) application:(UIApplication *)application shouldRestoreApplicationState:(NSCoder *)coder NS_AVAILABLE_IOS(6_0);
- (void) application:(UIApplication *)application willEncodeRestorableStateWithCoder:(NSCoder *)coder NS_AVAILABLE_IOS(6_0);
- (void) application:(UIApplication *)application didDecodeRestorableStateWithCoder:(NSCoder *)coder NS_AVAILABLE_IOS(6_0);

#pragma mark -- User Activity Continuation protocol adopted by UIApplication delegate --

// Called on the main thread as soon as the user indicates they want to continue an activity in your application. The NSUserActivity object may not be available instantly,
// so use this as an opportunity to show the user that an activity will be continued shortly.
// For each application:willContinueUserActivityWithType: invocation, you are guaranteed to get exactly one invocation of application:continueUserActivity: on success,
// or application:didFailToContinueUserActivityWithType:error: if an error was encountered.
- (BOOL)application:(UIApplication *)application willContinueUserActivityWithType:(NSString *)userActivityType NS_AVAILABLE_IOS(8_0);

// Called on the main thread after the NSUserActivity object is available. Use the data you stored in the NSUserActivity object to re-create what the user was doing.
// You can create/fetch any restorable objects associated with the user activity, and pass them to the restorationHandler. They will then have the UIResponder restoreUserActivityState: method
// invoked with the user activity. Invoking the restorationHandler is optional. It may be copied and invoked later, and it will bounce to the main thread to complete its work and call
// restoreUserActivityState on all objects.
- (BOOL)application:(UIApplication *)application continueUserActivity:(NSUserActivity *)userActivity restorationHandler:(void(^)(NSArray * __nullable restorableObjects))restorationHandler NS_AVAILABLE_IOS(8_0);

// If the user activity cannot be fetched after willContinueUserActivityWithType is called, this will be called on the main thread when implemented.
- (void)application:(UIApplication *)application didFailToContinueUserActivityWithType:(NSString *)userActivityType error:(NSError *)error NS_AVAILABLE_IOS(8_0);

// This is called on the main thread when a user activity managed by UIKit has been updated. You can use this as a last chance to add additional data to the userActivity.
- (void)application:(UIApplication *)application didUpdateUserActivity:(NSUserActivity *)userActivity NS_AVAILABLE_IOS(8_0);

#pragma mark -- CloudKit Sharing Invitation Handling --
// This will be called on the main thread after the user indicates they want to accept a CloudKit sharing invitation in your application.
// You should use the CKShareMetadata object's shareURL and containerIdentifier to schedule a CKAcceptSharesOperation, then start using
// the resulting CKShare and its associated record(s), which will appear in the CKContainer's shared database in a zone matching that of the record's owner.
- (void) application:(UIApplication *)application userDidAcceptCloudKitShareWithMetadata:(CKShareMetadata *)cloudKitShareMetadata NS_AVAILABLE_IOS(10_0);

@end

@interface UIApplication(UIApplicationDeprecated)

@property(nonatomic,getter=isProximitySensingEnabled) BOOL proximitySensingEnabled NS_DEPRECATED_IOS(2_0, 3_0) __TVOS_PROHIBITED; // default is NO. see UIDevice for replacement
- (void)setStatusBarHidden:(BOOL)hidden animated:(BOOL)animated NS_DEPRECATED_IOS(2_0, 3_2) __TVOS_PROHIBITED; // use -setStatusBarHidden:withAnimation:

// Explicit setting of the status bar orientation is more limited in iOS 6.0 and later.
@property(readwrite, nonatomic) UIInterfaceOrientation statusBarOrientation NS_DEPRECATED_IOS(2_0, 9_0, "Explicit setting of the status bar orientation is more limited in iOS 6.0 and later") __TVOS_PROHIBITED;
- (void)setStatusBarOrientation:(UIInterfaceOrientation)interfaceOrientation animated:(BOOL)animated NS_DEPRECATED_IOS(2_0, 9_0, "Explicit setting of the status bar orientation is more limited in iOS 6.0 and later") __TVOS_PROHIBITED;

// Setting the statusBarStyle does nothing if your application is using the default UIViewController-based status bar system.
@property(readwrite, nonatomic) UIStatusBarStyle statusBarStyle NS_DEPRECATED_IOS(2_0, 9_0, "Use -[UIViewController preferredStatusBarStyle]") __TVOS_PROHIBITED;
- (void)setStatusBarStyle:(UIStatusBarStyle)statusBarStyle animated:(BOOL)animated NS_DEPRECATED_IOS(2_0, 9_0, "Use -[UIViewController preferredStatusBarStyle]") __TVOS_PROHIBITED;

// Setting statusBarHidden does nothing if your application is using the default UIViewController-based status bar system.
@property(readwrite, nonatomic,getter=isStatusBarHidden) BOOL statusBarHidden NS_DEPRECATED_IOS(2_0, 9_0, "Use -[UIViewController prefersStatusBarHidden]") __TVOS_PROHIBITED;
- (void)setStatusBarHidden:(BOOL)hidden withAnimation:(UIStatusBarAnimation)animation NS_DEPRECATED_IOS(3_2, 9_0, "Use -[UIViewController prefersStatusBarHidden]") __TVOS_PROHIBITED;

- (BOOL)setKeepAliveTimeout:(NSTimeInterval)timeout handler:(void(^ __nullable)(void))keepAliveHandler NS_DEPRECATED_IOS(4_0, 9_0, "Please use PushKit for VoIP applications instead of calling this method") __TVOS_PROHIBITED;
- (void)clearKeepAliveTimeout NS_DEPRECATED_IOS(4_0, 9_0, "Please use PushKit for VoIP applications instead of calling this method") __TVOS_PROHIBITED;

@end

// If nil is specified for principalClassName, the value for NSPrincipalClass from the Info.plist is used. If there is no
// NSPrincipalClass key specified, the UIApplication class is used. The delegate class will be instantiated using init.
UIKIT_EXTERN int UIApplicationMain(int argc, char * _Nonnull * _Null_unspecified argv, NSString * _Nullable principalClassName, NSString * _Nullable delegateClassName);

UIKIT_EXTERN NSRunLoopMode const UITrackingRunLoopMode;

// These notifications are sent out after the equivalent delegate message is called
UIKIT_EXTERN NSNotificationName const UIApplicationDidEnterBackgroundNotification       NS_AVAILABLE_IOS(4_0);
UIKIT_EXTERN NSNotificationName const UIApplicationWillEnterForegroundNotification      NS_AVAILABLE_IOS(4_0);
UIKIT_EXTERN NSNotificationName const UIApplicationDidFinishLaunchingNotification;
UIKIT_EXTERN NSNotificationName const UIApplicationDidBecomeActiveNotification;
UIKIT_EXTERN NSNotificationName const UIApplicationWillResignActiveNotification;
UIKIT_EXTERN NSNotificationName const UIApplicationDidReceiveMemoryWarningNotification;
UIKIT_EXTERN NSNotificationName const UIApplicationWillTerminateNotification;
UIKIT_EXTERN NSNotificationName const UIApplicationSignificantTimeChangeNotification;
UIKIT_EXTERN NSNotificationName const UIApplicationWillChangeStatusBarOrientationNotification __TVOS_PROHIBITED; // userInfo contains NSNumber with new orientation
UIKIT_EXTERN NSNotificationName const UIApplicationDidChangeStatusBarOrientationNotification __TVOS_PROHIBITED;  // userInfo contains NSNumber with old orientation
UIKIT_EXTERN NSString *const UIApplicationStatusBarOrientationUserInfoKey __TVOS_PROHIBITED;            // userInfo dictionary key for status bar orientation
UIKIT_EXTERN NSNotificationName const UIApplicationWillChangeStatusBarFrameNotification __TVOS_PROHIBITED;       // userInfo contains NSValue with new frame
UIKIT_EXTERN NSNotificationName const UIApplicationDidChangeStatusBarFrameNotification __TVOS_PROHIBITED;        // userInfo contains NSValue with old frame
UIKIT_EXTERN NSString *const UIApplicationStatusBarFrameUserInfoKey __TVOS_PROHIBITED;                  // userInfo dictionary key for status bar frame
UIKIT_EXTERN NSNotificationName const UIApplicationBackgroundRefreshStatusDidChangeNotification API_AVAILABLE(ios(7.0), tvos(11.0));

UIKIT_EXTERN NSNotificationName const UIApplicationProtectedDataWillBecomeUnavailable    NS_AVAILABLE_IOS(4_0);
UIKIT_EXTERN NSNotificationName const UIApplicationProtectedDataDidBecomeAvailable       NS_AVAILABLE_IOS(4_0);

#if UIKIT_STRING_ENUMS
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsURLKey                   NS_SWIFT_NAME(url) NS_AVAILABLE_IOS(3_0); // userInfo contains NSURL with launch URL
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsSourceApplicationKey     NS_SWIFT_NAME(sourceApplication) NS_AVAILABLE_IOS(3_0); // userInfo contains NSString with launch app bundle ID
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsRemoteNotificationKey    NS_SWIFT_NAME(remoteNotification) NS_AVAILABLE_IOS(3_0) __TVOS_PROHIBITED; // userInfo contains NSDictionary with payload
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsLocalNotificationKey     NS_SWIFT_NAME(localNotification) NS_DEPRECATED_IOS(4_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenterDelegate didReceiveNotificationResponse:withCompletionHandler:]") __TVOS_PROHIBITED; // userInfo contains a UILocalNotification
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsAnnotationKey            NS_SWIFT_NAME(annotation) NS_AVAILABLE_IOS(3_2); // userInfo contains object with annotation property list
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsLocationKey              NS_SWIFT_NAME(location) NS_AVAILABLE_IOS(4_0); // app was launched in response to a CoreLocation event.
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsNewsstandDownloadsKey    NS_SWIFT_NAME(newsstandDownloads) NS_AVAILABLE_IOS(5_0) __TVOS_PROHIBITED; // userInfo contains an NSArray of NKAssetDownload identifiers
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsBluetoothCentralsKey     NS_SWIFT_NAME(bluetoothCentrals) NS_AVAILABLE_IOS(7_0); // userInfo contains an NSArray of CBCentralManager restore identifiers
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsBluetoothPeripheralsKey  NS_SWIFT_NAME(bluetoothPeripherals) NS_AVAILABLE_IOS(7_0); // userInfo contains an NSArray of CBPeripheralManager restore identifiers
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsShortcutItemKey          NS_SWIFT_NAME(shortcutItem) NS_AVAILABLE_IOS(9_0) __TVOS_PROHIBITED; // userInfo contains the UIApplicationShortcutItem used to launch the app.

// Key in options dict passed to application:[will | did]FinishLaunchingWithOptions and info for UIApplicationDidFinishLaunchingNotification
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsUserActivityDictionaryKey    NS_SWIFT_NAME(userActivityDictionary) NS_AVAILABLE_IOS(8_0); // Sub-Dictionary present in launch options when user activity is present
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsUserActivityTypeKey          NS_SWIFT_NAME(userActivityType) NS_AVAILABLE_IOS(8_0); // Key in user activity dictionary for the activity type
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsCloudKitShareMetadataKey NS_SWIFT_NAME(cloudKitShareMetadata) NS_AVAILABLE_IOS(10_0) __TVOS_PROHIBITED; // The presence of this key indicates that the app was launched in order to handle a CloudKit sharing invitation. The value of this key is a CKShareMetadata object.
#else
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsURLKey                   NS_AVAILABLE_IOS(3_0); // userInfo contains NSURL with launch URL
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsSourceApplicationKey     NS_AVAILABLE_IOS(3_0); // userInfo contains NSString with launch app bundle ID
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsRemoteNotificationKey    NS_AVAILABLE_IOS(3_0) __TVOS_PROHIBITED; // userInfo contains NSDictionary with payload
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsLocalNotificationKey     NS_DEPRECATED_IOS(4_0, 10_0, "Use UserNotifications Framework's -[UNUserNotificationCenterDelegate didReceiveNotificationResponse:withCompletionHandler:]") __TVOS_PROHIBITED; // userInfo contains a UILocalNotification
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsAnnotationKey            NS_AVAILABLE_IOS(3_2); // userInfo contains object with annotation property list
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsLocationKey              NS_AVAILABLE_IOS(4_0); // app was launched in response to a CoreLocation event.
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsNewsstandDownloadsKey    NS_AVAILABLE_IOS(5_0) __TVOS_PROHIBITED; // userInfo contains an NSArray of NKAssetDownload identifiers
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsBluetoothCentralsKey     NS_AVAILABLE_IOS(7_0); // userInfo contains an NSArray of CBCentralManager restore identifiers
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsBluetoothPeripheralsKey  NS_AVAILABLE_IOS(7_0); // userInfo contains an NSArray of CBPeripheralManager restore identifiers
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsShortcutItemKey          NS_AVAILABLE_IOS(9_0) __TVOS_PROHIBITED; // userInfo contains the UIApplicationShortcutItem used to launch the app.
// Key in options dict passed to application:[will | did]FinishLaunchingWithOptions and info for UIApplicationDidFinishLaunchingNotification
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsUserActivityDictionaryKey NS_AVAILABLE_IOS(8_0); // Sub-Dictionary present in launch options when user activity is present
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsUserActivityTypeKey NS_AVAILABLE_IOS(8_0); // Key in user activity dictionary for the activity type
UIKIT_EXTERN UIApplicationLaunchOptionsKey const UIApplicationLaunchOptionsCloudKitShareMetadataKey NS_AVAILABLE_IOS(10_0) __TVOS_PROHIBITED; // The presence of this key indicates that the app was launched in order to handle a CloudKit sharing invitation. The value of this key is a CKShareMetadata object.
#endif

UIKIT_EXTERN NSString *const UIApplicationOpenSettingsURLString NS_AVAILABLE_IOS(8_0);

// Keys for application:openURL:options:
#if UIKIT_STRING_ENUMS
UIKIT_EXTERN UIApplicationOpenURLOptionsKey const UIApplicationOpenURLOptionsSourceApplicationKey NS_SWIFT_NAME(sourceApplication) NS_AVAILABLE_IOS(9_0);   // value is an NSString containing the bundle ID of the originating application
UIKIT_EXTERN UIApplicationOpenURLOptionsKey const UIApplicationOpenURLOptionsAnnotationKey NS_SWIFT_NAME(annotation) NS_AVAILABLE_IOS(9_0);   // value is a property-list typed object corresponding to what the originating application passed in UIDocumentInteractionController's annotation property
UIKIT_EXTERN UIApplicationOpenURLOptionsKey const UIApplicationOpenURLOptionsOpenInPlaceKey NS_SWIFT_NAME(openInPlace) NS_AVAILABLE_IOS(9_0);   // value is a bool NSNumber. Copy the file before use if this value is NO, or is not present.
#else
UIKIT_EXTERN UIApplicationOpenURLOptionsKey const UIApplicationOpenURLOptionsSourceApplicationKey NS_AVAILABLE_IOS(9_0);   // value is an NSString containing the bundle ID of the originating application
UIKIT_EXTERN UIApplicationOpenURLOptionsKey const UIApplicationOpenURLOptionsAnnotationKey NS_AVAILABLE_IOS(9_0);   // value is a property-list typed object corresponding to what the originating application passed in UIDocumentInteractionController's annotation property
UIKIT_EXTERN UIApplicationOpenURLOptionsKey const UIApplicationOpenURLOptionsOpenInPlaceKey NS_AVAILABLE_IOS(9_0);   // value is a bool NSNumber, set to YES if the file needs to be copied before use
#endif

// This notification is posted after the user takes a screenshot (for example by pressing both the home and lock screen buttons)
UIKIT_EXTERN NSNotificationName const UIApplicationUserDidTakeScreenshotNotification NS_AVAILABLE_IOS(7_0);

// Extension point identifier constants
#if UIKIT_STRING_ENUMS
UIKIT_EXTERN UIApplicationExtensionPointIdentifier const UIApplicationKeyboardExtensionPointIdentifier NS_SWIFT_NAME(keyboard) NS_AVAILABLE_IOS(8_0);
#else
UIKIT_EXTERN UIApplicationExtensionPointIdentifier const UIApplicationKeyboardExtensionPointIdentifier NS_AVAILABLE_IOS(8_0);
#endif

#pragma mark -- openURL options --

// Option for openURL:options:CompletionHandler: only open URL if it is a valid universal link with an application configured to open it
// If there is no application configured, or the user disabled using it to open the link, completion handler called with NO
UIKIT_EXTERN NSString *const UIApplicationOpenURLOptionUniversalLinksOnly NS_AVAILABLE_IOS(10_0);

NS_ASSUME_NONNULL_END
