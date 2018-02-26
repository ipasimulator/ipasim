//
//  WKInterfaceDevice.h
//  WatchKit
//
//  Copyright (c) 2014-2015 Apple Inc. All rights reserved.
//

#import <CoreGraphics/CoreGraphics.h>
#import <WatchKit/WKDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class UIImage;

typedef NS_ENUM(NSInteger, WKHapticType) {
	WKHapticTypeNotification,
    WKHapticTypeDirectionUp,
    WKHapticTypeDirectionDown,
    WKHapticTypeSuccess,
    WKHapticTypeFailure,
    WKHapticTypeRetry,
    WKHapticTypeStart,
    WKHapticTypeStop,
    WKHapticTypeClick
} WK_AVAILABLE_WATCHOS_ONLY(2.0);

typedef NS_ENUM(NSInteger, WKInterfaceLayoutDirection) {
    WKInterfaceLayoutDirectionLeftToRight,
    WKInterfaceLayoutDirectionRightToLeft,
} WK_AVAILABLE_WATCHOS_ONLY(2.1);

typedef NS_ENUM(NSInteger, WKInterfaceSemanticContentAttribute) {
    WKInterfaceSemanticContentAttributeUnspecified,
    WKInterfaceSemanticContentAttributePlayback,         // for playback controls such as Play/RW/FF buttons and playhead scrubbers
    WKInterfaceSemanticContentAttributeSpatial,          // for controls that result in some sort of directional change in the UI
    WKInterfaceSemanticContentAttributeForceLeftToRight,
    WKInterfaceSemanticContentAttributeForceRightToLeft,
} WK_AVAILABLE_WATCHOS_ONLY(2.1);

typedef NS_ENUM(NSInteger, WKInterfaceDeviceWristLocation) {
    WKInterfaceDeviceWristLocationLeft,
    WKInterfaceDeviceWristLocationRight,
} WK_AVAILABLE_WATCHOS_ONLY(3.0);

typedef NS_ENUM(NSInteger, WKInterfaceDeviceCrownOrientation) {
    WKInterfaceDeviceCrownOrientationLeft,
    WKInterfaceDeviceCrownOrientationRight,
} WK_AVAILABLE_WATCHOS_ONLY(3.0);

#if TARGET_OS_WATCH
typedef NS_ENUM(NSInteger, WKWaterResistanceRating) {
    WKWaterResistanceRatingIPX7 NS_SWIFT_NAME(ipx7),
    WKWaterResistanceRatingWR50 NS_SWIFT_NAME(wr50),
} WK_AVAILABLE_WATCHOS_ONLY(3.0);
#endif

typedef NS_ENUM(NSInteger, WKInterfaceDeviceBatteryState) {
    WKInterfaceDeviceBatteryStateUnknown,
    WKInterfaceDeviceBatteryStateUnplugged,   // on battery, discharging
    WKInterfaceDeviceBatteryStateCharging,    // plugged in, less than 100%
    WKInterfaceDeviceBatteryStateFull,        // plugged in, at 100%
} WK_AVAILABLE_WATCHOS_ONLY(4.0);

@interface WKInterfaceDevice : NSObject

+ (WKInterfaceDevice *)currentDevice;

- (BOOL)addCachedImage:(UIImage *)image name:(NSString *)name WK_AVAILABLE_IOS_ONLY(8.2);
- (BOOL)addCachedImageWithData:(NSData *)imageData name:(NSString *)name WK_AVAILABLE_IOS_ONLY(8.2);
- (void)removeCachedImageWithName:(NSString *)name WK_AVAILABLE_IOS_ONLY(8.2);
- (void)removeAllCachedImages WK_AVAILABLE_IOS_ONLY(8.2);
@property (nonatomic, readonly, strong) NSDictionary<NSString*, NSNumber*> *cachedImages WK_AVAILABLE_IOS_ONLY(8.2); // name and size of cached images

@property (nonatomic, readonly) CGRect screenBounds;
@property (nonatomic, readonly) CGFloat screenScale;
@property (nonatomic,getter=isBatteryMonitoringEnabled) BOOL batteryMonitoringEnabled WK_AVAILABLE_WATCHOS_ONLY(4.0); // default is NO
@property (nonatomic, readonly) float batteryLevel WK_AVAILABLE_WATCHOS_ONLY(4.0); // 0 .. 1.0. -1.0 if WKInterfaceDeviceBatteryStateUnknown
@property (nonatomic, readonly) WKInterfaceDeviceBatteryState batteryState WK_AVAILABLE_WATCHOS_ONLY(4.0); // WKInterfaceDeviceBatteryStateUnknown if monitoring disabled
@property (nonatomic, readonly, copy)  NSString *preferredContentSizeCategory;
@property (nonatomic, readonly) WKInterfaceLayoutDirection layoutDirection WK_AVAILABLE_WATCHOS_ONLY(2.1);

@property (nonatomic,readonly) WKInterfaceDeviceWristLocation wristLocation WK_AVAILABLE_WATCHOS_ONLY(3.0);
@property (nonatomic,readonly) WKInterfaceDeviceCrownOrientation crownOrientation WK_AVAILABLE_WATCHOS_ONLY(3.0);

+ (WKInterfaceLayoutDirection)interfaceLayoutDirectionForSemanticContentAttribute:(WKInterfaceSemanticContentAttribute)semanticContentAttribute WK_AVAILABLE_WATCHOS_ONLY(2.1);

@property(nonatomic, readonly, copy) NSString *systemVersion  WK_AVAILABLE_WATCHOS_IOS(2.0,9.0); // e.g. @"2.0"
@property(nonatomic, readonly, copy) NSString *name           WK_AVAILABLE_WATCHOS_IOS(2.0,9.0); // e.g. "My Watch"
@property(nonatomic, readonly, copy) NSString *model          WK_AVAILABLE_WATCHOS_IOS(2.0,9.0); // e.g. @"Apple Watch"
@property(nonatomic, readonly, copy) NSString *localizedModel WK_AVAILABLE_WATCHOS_IOS(2.0,9.0); // localized version of model
@property(nonatomic, readonly, copy) NSString *systemName     WK_AVAILABLE_WATCHOS_IOS(2.0,9.0); // e.g. @"watchOS"

#if TARGET_OS_WATCH
@property (nonatomic,readonly) WKWaterResistanceRating waterResistanceRating WK_AVAILABLE_WATCHOS_ONLY(3.0);
#endif

- (void)playHaptic:(WKHapticType)type WK_AVAILABLE_WATCHOS_ONLY(2.0);
@end

NS_ASSUME_NONNULL_END
