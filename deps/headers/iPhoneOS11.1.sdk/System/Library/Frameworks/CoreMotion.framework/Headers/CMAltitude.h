/*
 *  CMAltitude.h
 *  CoreMotion
 *
 *  Copyright (c) 2014 Apple Inc. All rights reserved.
 *
 */

#import <Foundation/Foundation.h>
#import <CoreMotion/CMLogItem.h>
#import <CoreMotion/CMAvailability.h>

NS_ASSUME_NONNULL_BEGIN

/*
 *  CMAltitudeData
 *
 *  Discussion:
 *      Contains a single altimeter measurement.
 */
NS_CLASS_AVAILABLE(NA, 8_0) __TVOS_PROHIBITED
@interface CMAltitudeData : CMLogItem

/*
 *  relativeAltitude
 *
 *  Discussion:
 *    The relative altitude in meters to the starting altitude.
 *
 */
@property(readonly, nonatomic) NSNumber *relativeAltitude;

/*
 *  pressure
 *
 *  Discussion:
 *    The pressure in kPa.
 *
 */
@property(readonly, nonatomic) NSNumber *pressure;

@end

NS_ASSUME_NONNULL_END
