//
//  INRideFareLineItem.h
//  Intents
//
//  Copyright (c) 2016-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_CLASS_AVAILABLE(NA, 10_0) __TVOS_PROHIBITED __WATCHOS_AVAILABLE(3_0)
@interface INRideFareLineItem : NSObject <NSCopying, NSSecureCoding>

// A single line item in a set of pricing line items that describes
- (instancetype)initWithTitle:(NSString *)title price:(NSDecimalNumber *)price currencyCode:(NSString *)currencyCode NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@property (readonly, nonatomic) NSString *title; // e.g. "Base fare", or "+ per mile"
@property (readonly, nonatomic) NSDecimalNumber *price; // e.g. '4.50'
@property (readonly, nonatomic) NSString *currencyCode; // the ISO currency code for the currency for this price, e.g. "USD" for U.S. Dollar.

@end
