//
//  SKCloudServiceController.h
//  StoreKit
//
//  Copyright © 2015-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <StoreKit/StoreKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SKCloudServiceAuthorizationStatus) {
    SKCloudServiceAuthorizationStatusNotDetermined,
    SKCloudServiceAuthorizationStatusDenied,
    SKCloudServiceAuthorizationStatusRestricted,
    SKCloudServiceAuthorizationStatusAuthorized,
} NS_ENUM_AVAILABLE_IOS(9_3);

typedef NS_OPTIONS(NSUInteger, SKCloudServiceCapability) {
    SKCloudServiceCapabilityNone                           = 0,
    SKCloudServiceCapabilityMusicCatalogPlayback           = 1 << 0,
    SKCloudServiceCapabilityMusicCatalogSubscriptionEligible    NS_ENUM_AVAILABLE_IOS(10_1)  = 1 << 1,
    SKCloudServiceCapabilityAddToCloudMusicLibrary         = 1 << 8,
} NS_AVAILABLE_IOS(9_3);

SK_EXTERN_CLASS_AVAILABLE(9_3) @interface SKCloudServiceController : NSObject

+ (SKCloudServiceAuthorizationStatus)authorizationStatus;
+ (void)requestAuthorization:(void(^)(SKCloudServiceAuthorizationStatus status))handler;

- (void)requestCapabilitiesWithCompletionHandler:(void(^)(SKCloudServiceCapability capabilities, NSError * _Nullable error))completionHandler;

- (void)requestStorefrontCountryCodeWithCompletionHandler:(void(^)(NSString * _Nullable storefrontCountryCode, NSError * _Nullable error))completionHandler NS_AVAILABLE_IOS(11_0);
- (void)requestStorefrontIdentifierWithCompletionHandler:(void(^)(NSString * _Nullable storefrontIdentifier, NSError * _Nullable error))completionHandler;

- (void)requestUserTokenForDeveloperToken:(NSString *)developerToken completionHandler:(void(^)(NSString * _Nullable userToken, NSError * _Nullable error))completionHandler NS_AVAILABLE_IOS(11_0);
- (void)requestPersonalizationTokenForClientToken:(NSString *)clientToken withCompletionHandler:(void(^)(NSString * _Nullable personalizationToken, NSError * _Nullable error))completionHandler API_DEPRECATED_WITH_REPLACEMENT("requestUserTokenForDeveloperToken:completionHandler:", ios(10.3, 11.0));

@end

SK_EXTERN NSNotificationName const SKCloudServiceCapabilitiesDidChangeNotification NS_AVAILABLE_IOS(9_3);
SK_EXTERN NSNotificationName const SKStorefrontCountryCodeDidChangeNotification NS_AVAILABLE_IOS(11_0);
SK_EXTERN NSNotificationName const SKStorefrontIdentifierDidChangeNotification NS_AVAILABLE_IOS(9_3);

NS_ASSUME_NONNULL_END
