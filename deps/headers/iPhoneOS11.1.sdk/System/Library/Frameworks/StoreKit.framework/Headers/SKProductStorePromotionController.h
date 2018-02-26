//
//  SKProductStorePromotionController.h
//  StoreKit
//
//  Copyright © 2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <StoreKit/StoreKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class SKProduct;

typedef NS_ENUM(NSInteger, SKProductStorePromotionVisibility) {
    SKProductStorePromotionVisibilityDefault,
    SKProductStorePromotionVisibilityShow,
    SKProductStorePromotionVisibilityHide,
} NS_ENUM_AVAILABLE_IOS(11_0);

SK_EXTERN_CLASS_AVAILABLE(11_0) @interface SKProductStorePromotionController : NSObject

+ (instancetype)defaultController NS_AVAILABLE_IOS(11_0);

- (void)fetchStorePromotionVisibilityForProduct:(SKProduct *)product completionHandler:(nullable void (^)(SKProductStorePromotionVisibility storePromotionVisibility, NSError * _Nullable error))completionHandler NS_AVAILABLE_IOS(11_0);
- (void)updateStorePromotionVisibility:(SKProductStorePromotionVisibility)promotionVisibility forProduct:(SKProduct *)product completionHandler:(nullable void (^)(NSError * _Nullable error))completionHandler NS_SWIFT_NAME(update(storePromotionVisibility:for:completionHandler:)) NS_AVAILABLE_IOS(11_0);

- (void)fetchStorePromotionOrderWithCompletionHandler:(nullable void (^)(NSArray<SKProduct *> *storePromotionOrder, NSError * _Nullable error))completionHandler NS_AVAILABLE_IOS(11_0);
- (void)updateStorePromotionOrder:(NSArray<SKProduct *> *)storePromotionOrder completionHandler:(nullable void (^)(NSError * _Nullable error))completionHandler NS_SWIFT_NAME(update(storePromotionOrder:completionHandler:)) NS_AVAILABLE_IOS(11_0);

@end

NS_ASSUME_NONNULL_END
