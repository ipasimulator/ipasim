//
//  SKProduct.h
//  StoreKit
//
//  Copyright 2009 Apple, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <StoreKit/StoreKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

SK_EXTERN_CLASS_AVAILABLE(3_0) @interface SKProduct : NSObject {
@private
    id _internal;
}

@property(nonatomic, readonly) NSString *localizedDescription NS_AVAILABLE_IOS(3_0);

@property(nonatomic, readonly) NSString *localizedTitle NS_AVAILABLE_IOS(3_0);

@property(nonatomic, readonly) NSDecimalNumber *price NS_AVAILABLE_IOS(3_0);

@property(nonatomic, readonly) NSLocale *priceLocale NS_AVAILABLE_IOS(3_0);

@property(nonatomic, readonly) NSString *productIdentifier NS_AVAILABLE_IOS(3_0);

// YES if this product has content downloadable using SKDownload
@property(nonatomic, readonly, getter=isDownloadable) BOOL downloadable NS_AVAILABLE_IOS(6_0);

// Sizes in bytes (NSNumber [long long]) of the downloads available for this product
@property(nonatomic, readonly) NSArray<NSNumber *> *downloadContentLengths NS_AVAILABLE_IOS(6_0);

// Version of the downloadable content
@property(nonatomic, readonly) NSString *downloadContentVersion NS_AVAILABLE_IOS(6_0);

@end

NS_ASSUME_NONNULL_END
