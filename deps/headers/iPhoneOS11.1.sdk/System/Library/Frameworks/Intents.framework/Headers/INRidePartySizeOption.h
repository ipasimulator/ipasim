//
//  INRidePartySizeOption.h
//  Intents
//
//  Copyright (c) 2016-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@class INPriceRange;

NS_ASSUME_NONNULL_BEGIN

NS_CLASS_AVAILABLE(NA, 10_0) __TVOS_PROHIBITED __WATCHOS_AVAILABLE(3_0)
@interface INRidePartySizeOption : NSObject <NSCopying, NSSecureCoding>

// A single party size in a set of party size selections. Each size may have a different price range.
- (instancetype)initWithPartySizeRange:(NSRange)partySizeRange sizeDescription:(NSString *)sizeDescription priceRange:(nullable INPriceRange *)priceRange NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@property (readonly, NS_NONATOMIC_IOSONLY) NSRange partySizeRange; // The number of people allowed, e.g. NSMakeRange(1, 0) for one person, or NSMakeRange(1, 2) for 1 to 3 people.
@property (readonly, NS_NONATOMIC_IOSONLY) NSString *sizeDescription; // e.g. "1 passenger" or "1-3 passengers".
@property (readonly, nullable, NS_NONATOMIC_IOSONLY) INPriceRange *priceRange; // the price range for this party size, which may be different from the indicative price range for the ride. If nil, the price range for the associated ride is valid instead.

@end

NS_ASSUME_NONNULL_END

