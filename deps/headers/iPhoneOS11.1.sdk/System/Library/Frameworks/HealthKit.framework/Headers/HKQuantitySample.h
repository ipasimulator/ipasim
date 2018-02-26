//
//  HKQuantitySample.h
//  HealthKit
//
//  Copyright (c) 2013-2014 Apple Inc. All rights reserved.
//

#import <HealthKit/HKSample.h>

NS_ASSUME_NONNULL_BEGIN

@class HKQuantity;
@class HKQuantityType;

/*!
 @class         HKQuantitySample
 @abstract      An HKObject subclass representing a quantity measurement.
 */
HK_EXTERN API_AVAILABLE(ios(8.0), watchos(2.0))
@interface HKQuantitySample : HKSample

@property (readonly, strong) HKQuantityType *quantityType;
@property (readonly, strong) HKQuantity *quantity;

/*!
 @method        quantitySampleWithType:quantity:startDate:endDate:
 @abstract      Creates a new HKQuantitySample with the given type, quantity, start date, and end date.
 @discussion    The quantity must have a unit that is compatible with the given quantity type.
                See -[HKQuantityType isCompatibleWithUnit:].
 */
+ (instancetype)quantitySampleWithType:(HKQuantityType *)quantityType
                              quantity:(HKQuantity *)quantity
                             startDate:(NSDate *)startDate
                               endDate:(NSDate *)endDate;

/*!
 @method        quantitySampleWithType:quantity:startDate:endDate:metadata:
 @abstract      Creates a new HKQuantitySample with the given type, quantity, start date, end date, and metadata.
 @discussion    The quantity must have a unit that is compatible with the given quantity type.
                See -[HKQuantityType isCompatibleWithUnit:].
 */
+ (instancetype)quantitySampleWithType:(HKQuantityType *)quantityType
                              quantity:(HKQuantity *)quantity
                             startDate:(NSDate *)startDate
                               endDate:(NSDate *)endDate
                              metadata:(nullable NSDictionary<NSString *, id> *)metadata;

/*!
 @method        quantitySampleWithType:quantity:startDate:endDate:device:metadata:
 @abstract      Creates a new HKQuantitySample with the given type, quantity, start date, end date, and metadata.
 @param         quantityType    The type of the sample.
 @param         startDate       The start date of the sample.
 @param         endDate         The end date of the sample.
 @param         device          The HKDevice that generated the sample (optional).
 @param         metadata        Metadata for the sample (optional).
 @discussion    The quantity must have a unit that is compatible with the given quantity type.
                See -[HKQuantityType isCompatibleWithUnit:].
 */
+ (instancetype)quantitySampleWithType:(HKQuantityType *)quantityType
                              quantity:(HKQuantity *)quantity
                             startDate:(NSDate *)startDate
                               endDate:(NSDate *)endDate
                                device:(nullable HKDevice *)device
                              metadata:(nullable NSDictionary<NSString *, id> *)metadata API_AVAILABLE(ios(9.0), watchos(2.0));

@end

// Predicate Key Paths
HK_EXTERN NSString * const HKPredicateKeyPathQuantity API_AVAILABLE(ios(8.0), watchos(2.0));

NS_ASSUME_NONNULL_END
