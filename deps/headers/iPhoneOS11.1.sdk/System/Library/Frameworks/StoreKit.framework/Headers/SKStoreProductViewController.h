//
//  SKStoreProductViewController.h
//  StoreKit
//
//  Copyright (c) 2012 Apple, Inc. All rights reserved.
//

#import <StoreKit/StoreKitDefines.h>
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@protocol SKStoreProductViewControllerDelegate;

/* View controller to display iTunes Store product information */
SK_EXTERN_CLASS_AVAILABLE(6_0) __TVOS_PROHIBITED @interface SKStoreProductViewController : UIViewController

// Delegate for product page events
@property(nonatomic, assign, nullable) id <SKStoreProductViewControllerDelegate> delegate NS_AVAILABLE_IOS(6_0);

// Load product view for the product with the given parameters.  See below for parameters (SKStoreProductParameter*).
// Block is invoked when the load finishes.
- (void)loadProductWithParameters:(NSDictionary<NSString *, id> *)parameters completionBlock:(nullable void(^)(BOOL result, NSError * __nullable error))block NS_AVAILABLE_IOS(6_0);

@end


@protocol SKStoreProductViewControllerDelegate <NSObject>

@optional

// Sent if the user requests that the page be dismissed
- (void)productViewControllerDidFinish:(SKStoreProductViewController *)viewController __TVOS_PROHIBITED NS_AVAILABLE_IOS(6_0);

@end


// iTunes Store item identifier (NSNumber) of the product
SK_EXTERN NSString * const SKStoreProductParameterITunesItemIdentifier NS_AVAILABLE_IOS(6_0);

// SKU for the In-App Purchase product (NSString) to render at the top of the product page
SK_EXTERN NSString * const SKStoreProductParameterProductIdentifier NS_AVAILABLE_IOS(11_0);

// iTunes Store affiliate token (NSString)
SK_EXTERN NSString * const SKStoreProductParameterAffiliateToken NS_AVAILABLE_IOS(8_0);

// iTunes Store affiliate campaign token (NSString)
SK_EXTERN NSString * const SKStoreProductParameterCampaignToken NS_AVAILABLE_IOS(8_0);

// Analytics provider token (NSString)
SK_EXTERN NSString * const SKStoreProductParameterProviderToken NS_AVAILABLE_IOS(8_3);

// Advertising partner token (NSString)
SK_EXTERN NSString * const SKStoreProductParameterAdvertisingPartnerToken NS_AVAILABLE_IOS(9_3);

NS_ASSUME_NONNULL_END
