//
//  SKCloudServiceSetupViewController.h
//  StoreKit
//
//  Copyright © 2016-2017 Apple Inc. All rights reserved.
//

#import <StoreKit/StoreKitDefines.h>
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

typedef NSString * SKCloudServiceSetupOptionsKey NS_STRING_ENUM;
typedef NSString * SKCloudServiceSetupAction NS_STRING_ENUM;
typedef NSString * SKCloudServiceSetupMessageIdentifier NS_STRING_ENUM;

@protocol SKCloudServiceSetupViewControllerDelegate;

/// View controller to allow user to setup iTunes Store account for cloud service, such as Apple Music subscription.
SK_EXTERN_CLASS_AVAILABLE(10_1) __TVOS_PROHIBITED @interface SKCloudServiceSetupViewController : UIViewController

/// Optional delegate.
@property (nonatomic, nullable, weak) id <SKCloudServiceSetupViewControllerDelegate> delegate;

/// Load cloud service setup view with the given options.
/// Block is invoked on the main thread when the load finishes.
- (void)loadWithOptions:(NSDictionary<SKCloudServiceSetupOptionsKey, id> *)options completionHandler:(nullable void (^)(BOOL result, NSError * _Nullable error))completionHandler;

@end


@protocol SKCloudServiceSetupViewControllerDelegate <NSObject>

@optional

/// Sent when the view controller was dismissed.
- (void)cloudServiceSetupViewControllerDidDismiss:(SKCloudServiceSetupViewController *)cloudServiceSetupViewController __TVOS_PROHIBITED NS_AVAILABLE_IOS(10_1);

@end


/// Action for setup entry point (of type SKCloudServiceSetupAction).
SK_EXTERN SKCloudServiceSetupOptionsKey const SKCloudServiceSetupOptionsActionKey NS_SWIFT_NAME(action) NS_AVAILABLE_IOS(10_1);

/// Identifier of the iTunes Store item the user is trying to access which requires cloud service setup (NSNumber).
SK_EXTERN SKCloudServiceSetupOptionsKey const SKCloudServiceSetupOptionsITunesItemIdentifierKey NS_SWIFT_NAME(iTunesItemIdentifier) NS_AVAILABLE_IOS(10_1);

/// iTunes Store affiliate token (NSString).
SK_EXTERN SKCloudServiceSetupOptionsKey const SKCloudServiceSetupOptionsAffiliateTokenKey NS_SWIFT_NAME(affiliateToken) NS_AVAILABLE_IOS(10_3);

/// iTunes Store affiliate campaign token (NSString).
SK_EXTERN SKCloudServiceSetupOptionsKey const SKCloudServiceSetupOptionsCampaignTokenKey NS_SWIFT_NAME(campaignToken) NS_AVAILABLE_IOS(10_3);

/// Identifier used to select the main message presented to the user for this setup view (SKCloudServiceSetupMessageIdentifier).
/// When missing, the setup view will be configured in a way that is equivalent to using SKCloudServiceSetupMessageIdentifierJoin.
SK_EXTERN SKCloudServiceSetupOptionsKey const SKCloudServiceSetupOptionsMessageIdentifierKey NS_SWIFT_NAME(messageIdentifier) NS_AVAILABLE_IOS(11_0);

// Supported actions for setup entry point.

SK_EXTERN SKCloudServiceSetupAction const SKCloudServiceSetupActionSubscribe NS_AVAILABLE_IOS(10_1);

// Supported message identifiers.

SK_EXTERN SKCloudServiceSetupMessageIdentifier const SKCloudServiceSetupMessageIdentifierJoin NS_AVAILABLE_IOS(11_0);
SK_EXTERN SKCloudServiceSetupMessageIdentifier const SKCloudServiceSetupMessageIdentifierConnect NS_AVAILABLE_IOS(11_0);
SK_EXTERN SKCloudServiceSetupMessageIdentifier const SKCloudServiceSetupMessageIdentifierAddMusic NS_AVAILABLE_IOS(11_0);
SK_EXTERN SKCloudServiceSetupMessageIdentifier const SKCloudServiceSetupMessageIdentifierPlayMusic NS_AVAILABLE_IOS(11_0);

NS_ASSUME_NONNULL_END
