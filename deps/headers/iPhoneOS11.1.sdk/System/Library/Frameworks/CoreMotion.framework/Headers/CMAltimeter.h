/*
 *  CMAltimeter.h
 *  CoreMotion
 *
 *  Copyright (c) 2014 Apple Inc. All rights reserved.
 *
 */

#import <Foundation/Foundation.h>
#import <CoreMotion/CMAltitude.h>
#import <CoreMotion/CMAvailability.h>
#import <CoreMotion/CMAuthorization.h>

NS_ASSUME_NONNULL_BEGIN

/*
 *  CMAltitudeHandler
 *
 *  Discussion:
 *    Typedef of block to be invoked when the device's altitude is updated.
 */
typedef void (^CMAltitudeHandler)(CMAltitudeData * __nullable altitudeData, NSError * __nullable error) NS_AVAILABLE(NA,8_0) __TVOS_PROHIBITED;

/*
 *  CMAltimeter
 *
 *  Discussion:
 *		CMAltimeter provides information about the altitude of the device.
 */
NS_CLASS_AVAILABLE(NA,8_0) __TVOS_PROHIBITED
@interface CMAltimeter : NSObject

/*
 *  isRelativeAltitudeAvailable
 *
 *  Discussion:
 *		Determines whether the device supports reporting relative altitude changes.
 */
+ (BOOL)isRelativeAltitudeAvailable;

/*
 *  authorizationStatus
 *
 *  Discussion:
 *		Returns the current authorization status for altimeter.
 */
+ (CMAuthorizationStatus)authorizationStatus NS_AVAILABLE(NA, 11_0) __WATCHOS_AVAILABLE(4_0);

/*
 *  startRelativeAltitudeUpdatesToQueue:withHandler:
 *
 *  Discussion:
 *		Starts relative altitude updates, providing data to the given handler on the given queue
 *		every few seconds. The first altitude update will be established as the reference altitude
 *		and have relative altitude 0.
 *
 *		Calls to start must be balanced with calls to stopRelativeAltitudeUpdates even if an error
 *		is returned to the handler.
 */
- (void)startRelativeAltitudeUpdatesToQueue:(NSOperationQueue *)queue withHandler:(CMAltitudeHandler)handler;

/*
 *  stopRelativeAltitudeUpdates
 *
 *  Discussion:
 *      Stops relative altitude updates.
 */
- (void)stopRelativeAltitudeUpdates;

@end

NS_ASSUME_NONNULL_END
