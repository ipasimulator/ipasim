//
//  PKSuicaPassProperties.h
//  PassKit
//
//  Copyright (c) 2016 Apple, Inc. All rights reserved.
//
//

#import <Foundation/Foundation.h>

@class PKPass;

NS_ASSUME_NONNULL_BEGIN

API_AVAILABLE(ios(10.1), watchos(3.1))
@interface PKSuicaPassProperties : NSObject

/// Properties for a given pass, or nil if the pass doesn’t support the set of properties being requested
+ (nullable instancetype)passPropertiesForPass:(PKPass *)pass;

@property (nonatomic, copy, readonly) NSDecimalNumber *transitBalance;
@property (nonatomic, copy, readonly) NSString *transitBalanceCurrencyCode;

@property (nonatomic, assign, readonly, getter=isInStation) BOOL inStation;
/// Note: isInShinkansenStation is not a subset of isInStation.
@property (nonatomic, assign, readonly, getter=isInShinkansenStation) BOOL inShinkansenStation;

@property (nonatomic, assign, readonly, getter=isGreenCarTicketUsed) BOOL greenCarTicketUsed;
@property (nonatomic, assign, readonly, getter=isBlacklisted) BOOL blacklisted;

@end

NS_ASSUME_NONNULL_END
