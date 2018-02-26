//
//  SKReceiptRefreshRequest.h
//  StoreKit
//
//  Copyright (c) 2013 Apple, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <StoreKit/SKRequest.h>
#import <StoreKit/StoreKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

SK_EXTERN_CLASS_AVAILABLE(7_0) @interface SKReceiptRefreshRequest : SKRequest

- (instancetype)initWithReceiptProperties:(nullable NSDictionary<NSString *, id> *)properties NS_AVAILABLE_IOS(7_0);
@property (nonatomic, readonly, nullable) NSDictionary<NSString *, id> *receiptProperties NS_AVAILABLE_IOS(7_0);

@end

SK_EXTERN void SKTerminateForInvalidReceipt(void) NS_AVAILABLE_IOS(7_1);

// Receipt properties for sandbox testing:
SK_EXTERN NSString * const SKReceiptPropertyIsExpired NS_AVAILABLE_IOS(7_0);  // NSNumber BOOL, defaults to NO
SK_EXTERN NSString * const SKReceiptPropertyIsRevoked NS_AVAILABLE_IOS(7_0);  // NSNumber BOOL, defaults to NO
SK_EXTERN NSString * const SKReceiptPropertyIsVolumePurchase NS_AVAILABLE_IOS(7_0);  // NSNumber BOOL, defaults to NO

NS_ASSUME_NONNULL_END
