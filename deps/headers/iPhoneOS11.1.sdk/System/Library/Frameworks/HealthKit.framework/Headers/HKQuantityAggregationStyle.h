//
//  HKQuantityAggregationStyle.h
//  HealthKit
//
//  Copyright (c) 2013-2017 Apple Inc. All rights reserved.
//

/*!
 @enum          HKQuantityAggregationStyle
 @discussion    Describes how quantities can be aggregated over time.
 
 @constant      HKQuantityAggregationStyleCumulative    Samples may be summed over a time interval.
 @constant      HKQuantityAggregationStyleDiscrete      Samples may be averaged over a time interval.
 */
typedef NS_ENUM(NSInteger, HKQuantityAggregationStyle) {
    HKQuantityAggregationStyleCumulative = 0,
    HKQuantityAggregationStyleDiscrete,
} API_AVAILABLE(ios(8.0), watchos(2.0));
