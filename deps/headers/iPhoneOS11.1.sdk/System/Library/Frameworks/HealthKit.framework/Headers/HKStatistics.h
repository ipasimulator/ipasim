//
//  HKStatistics.h
//  HealthKit
//
//  Copyright (c) 2014 Apple Inc. All rights reserved.
//

#import <HealthKit/HKDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class HKQuantity;
@class HKQuantityType;
@class HKSource;

/*!
 @enum          HKStatisticsOptions
 @abstract      Options for specifying which statistics to calculate
 @discussion    When querying for HKStatistics objects, an options bitmask will specify which statistics will be 
                calculated.
 
                Statistics are classified as discrete or cumulative.  If a discrete statistics option is specified for a
                cumulative HKQuantityType, an exception will be thrown.  If a cumulative statistics options is specified
                for a discrete HKQuantityType, an exception will also be thrown.
 
 @constant      HKStatisticsOptionNone
 @constant      HKStatisticsOptionSeparateBySource
 @constant      HKStatisticsOptionDiscreteAverage   Calculate averageQuantity when creating statistics.
 @constant      HKStatisticsOptionDiscreteMin       Calculate minQuantity when creating statistics.
 @constant      HKStatisticsOptionDiscreteMax       Calculate maxQuantity when creating statistics.
 @constant      HKStatisticsOptionCumulativeSum     Calculate sumQuantity when creating statistics.
 */
typedef NS_OPTIONS(NSUInteger, HKStatisticsOptions) {
    HKStatisticsOptionNone              		= 0,
    HKStatisticsOptionSeparateBySource          = 1 << 0,
    HKStatisticsOptionDiscreteAverage           = 1 << 1,
    HKStatisticsOptionDiscreteMin               = 1 << 2,
    HKStatisticsOptionDiscreteMax               = 1 << 3,
    HKStatisticsOptionCumulativeSum             = 1 << 4,
} API_AVAILABLE(ios(8.0), watchos(2.0));

/*!
 @class         HKStatistics
 @abstract      Represents statistics for quantity samples over a period of time.
 */
HK_EXTERN API_AVAILABLE(ios(8.0), watchos(2.0))
@interface HKStatistics : NSObject <NSSecureCoding, NSCopying>

@property (readonly, strong) HKQuantityType *quantityType;
@property (readonly, strong) NSDate *startDate;
@property (readonly, strong) NSDate *endDate;
@property (readonly, strong, nullable) NSArray<HKSource *> *sources;

- (instancetype)init NS_UNAVAILABLE;

/* Discrete Quantities */

/*!
 @method        averageQuantityForSource:
 @abstract      Returns the average quantity for the given source in the time period represented by the receiver.
 @discussion    If HKStatisticsOptionSeparateBySource is not specified, then this will always be nil.
 */
- (nullable HKQuantity *)averageQuantityForSource:(HKSource *)source;

/*!
 @method        averageQuantity
 @abstract      Returns the average quantity in the time period represented by the receiver.
 */
- (nullable HKQuantity *)averageQuantity;

/*!
 @method        minimumQuantityForSource:
 @abstract      Returns the minimum quantity for the given source in the time period represented by the receiver.
 @discussion    If HKStatisticsOptionSeparateBySource is not specified, then this will always be nil.
 */
- (nullable HKQuantity *)minimumQuantityForSource:(HKSource *)source;

/*!
 @method        minimumQuantity
 @abstract      Returns the minimum quantity in the time period represented by the receiver.
 */
- (nullable HKQuantity *)minimumQuantity;

/*!
 @method        maximumQuantityForSource:
 @abstract      Returns the maximum quantity for the given source in the time period represented by the receiver.
 @discussion    If HKStatisticsOptionSeparateBySource is not specified, then this will always be nil.
 */
- (nullable HKQuantity *)maximumQuantityForSource:(HKSource *)source;

/*!
 @method        maximumQuantity
 @abstract      Returns the maximum quantity in the time period represented by the receiver.
 */
- (nullable HKQuantity *)maximumQuantity;

/* Cumulative Quantities */

/*!
 @method        sumQuantityForSource:
 @abstract      Returns the sum quantity for the given source in the time period represented by the receiver.
 @discussion    If HKStatisticsOptionSeparateBySource is not specified, then this will always be nil.
 */
- (nullable HKQuantity *)sumQuantityForSource:(HKSource *)source;

/*!
 @method        sumQuantity
 @abstract      Returns the sum of quantities in the time period represented by the receiver.
 */
- (nullable HKQuantity *)sumQuantity;

@end

NS_ASSUME_NONNULL_END
