/*
 *  CMMotionManager.h
 *  CoreMotion
 *
 *  Copyright (c) 2010 Apple Inc. All rights reserved.
 *
 */

#import <Foundation/Foundation.h>

#import <CoreMotion/CMAccelerometer.h>
#import <CoreMotion/CMGyro.h>
#import <CoreMotion/CMDeviceMotion.h>
#import <CoreMotion/CMMagnetometer.h>

#import <CoreMotion/CMAvailability.h>

NS_ASSUME_NONNULL_BEGIN

/*
 * There are two methods to receive data from CMMotionManager: push and pull.
 *
 * Before using either method, be sure to set the update interval property
 * appropriate to the type of data you're interested in. These properties are:
 * accelerometerUpdateInterval, gyroUpdateInterval, and deviceMotionUpdateInterval.
 *
 * To use the pull method, simply call startAccelerometerUpdates, startGyroUpdates,
 * and/or startDeviceMotionUpdates, depending on the type of data desired. Then,
 * whenever a new sample of data is desired, simply examine the appropriate
 * CMMotionManager property (accelerometerData, gyroData, or deviceMotion).
 *
 * To use the push method, simply call startAccelerometerUpdatesToQueue:withHandler:,
 * startGyroUpdatesToQueue:withHandler:, and/or
 * startDeviceMotionUpdatesToQueue:withHandler:, depending on the type of data
 * desired. You'll need to pass an NSOperationQueue and block to each call. When a new sample of
 * data arrives, a new instance of the block will be added to the appropriate NSOperationQueue.
 * When you stop the updates (see below), all operations in the given NSOperationQueue will be
 * cancelled, so it is recommended to pass CMMotionManager a queue that will not be used in other
 * contexts.
 *
 * Regardless of whether you used push or pull, when you're done, be sure to call the stop method
 * appropriate for the type of updates you started.  These methods are: stopAccelerometerUpdates,
 * stopGyroUpdates, and stopDeviceMotionUpdates.
 *
 */

/*
 *  CMAccelerometerHandler
 *
 *  Discussion:
 *    Typedef of block to be invoked when accelerometer data is available.
 */
typedef void (^CMAccelerometerHandler)(CMAccelerometerData * __nullable accelerometerData, NSError * __nullable error) __TVOS_PROHIBITED;

/*
 *  CMGyroHandler
 *
 *  Discussion:
 *    Typedef of block to be invoked when gyro data is available.
 */
typedef void (^CMGyroHandler)(CMGyroData * __nullable gyroData, NSError * __nullable error) __TVOS_PROHIBITED;

/*
 *  CMDeviceMotionHandler
 *
 *  Discussion:
 *    Typedef of block to be invoked when device motion data is available.
 */
typedef void (^CMDeviceMotionHandler)(CMDeviceMotion * __nullable motion, NSError * __nullable error) __TVOS_PROHIBITED;

/*
 *  CMMagnetometerHandler
 *
 *  Discussion:
 *    Typedef of block to be invoked when magnetometer data is available.
 */
typedef void (^CMMagnetometerHandler)(CMMagnetometerData * __nullable magnetometerData, NSError * __nullable error) NS_AVAILABLE(NA, 5_0) __TVOS_PROHIBITED;

/*
 *  CMMotionManager
 *
 *  Discussion:
 *    The CMMotionManager object is your entry point to the motion service.
 */
NS_CLASS_AVAILABLE(NA, 4_0)
@interface CMMotionManager : NSObject
{
@private
	id _internal;
}

/*
 *  accelerometerUpdateInterval
 *
 *  Discussion:
 *    The interval at which to deliver accelerometer data to the specified
 *    handler once startAccelerometerUpdatesToQueue:withHandler: is called.
 *    The units are in seconds. The value of this property is capped to
 *    certain minimum and maximum values. The maximum value is determined by
 *    the maximum frequency supported by the hardware. If sensitive to the
 *    interval of acceleration data, an application should always check the
 *    timestamps on the delivered CMAcceleration instances to determine the
 *    true update interval.
 */
@property(assign, nonatomic) NSTimeInterval accelerometerUpdateInterval __TVOS_PROHIBITED;

/*
 *  accelerometerAvailable
 *
 *  Discussion:
 *    Determines whether accelerometer is available.
 */
@property(readonly, nonatomic, getter=isAccelerometerAvailable) BOOL accelerometerAvailable __TVOS_PROHIBITED;

/*
 *  accelerometerActive
 *
 *  Discussion:
 *    Determines whether the CMMotionManager is currently providing
 *    accelerometer updates.
 */
@property(readonly, nonatomic, getter=isAccelerometerActive) BOOL accelerometerActive __TVOS_PROHIBITED;

/*
 *  accelerometerData
 *
 *  Discussion:
 *    Returns the latest sample of accelerometer data, or nil if none is available.
 */

@property(readonly, nullable) CMAccelerometerData *accelerometerData __TVOS_PROHIBITED;

/*
 *  startAccelerometerUpdates
 *
 *  Discussion:
 *    Starts accelerometer updates with no handler. To receive the latest accelerometer data
 *    when desired, examine the accelerometerData property.
 */
- (void)startAccelerometerUpdates __TVOS_PROHIBITED;

/*
 *  startAccelerometerUpdatesToQueue:withHandler:
 *
 *  Discussion:
 *    Starts accelerometer updates, providing data to the given handler through the given queue.
 *    Note that when the updates are stopped, all operations in the
 *    given NSOperationQueue will be cancelled.
 */
- (void)startAccelerometerUpdatesToQueue:(NSOperationQueue *)queue withHandler:(CMAccelerometerHandler)handler __TVOS_PROHIBITED;

/*
 *  stopAccelerometerUpdates
 *
 *  Discussion:
 *    Stop accelerometer updates.
 */
- (void)stopAccelerometerUpdates __TVOS_PROHIBITED;

/*
 *  gyroUpdateInterval
 *
 *  Discussion:
 *    The interval at which to deliver gyro data to the specified
 *    handler once startGyroUpdatesToQueue:withHandler: is called.
 *    The units are in seconds. The value of this property is capped to
 *    certain minimum and maximum values. The maximum value is determined by
 *    the maximum frequency supported by the hardware. If sensitive to the
 *    interval of gyro data, an application should always check the
 *    timestamps on the delivered CMGyroData instances to determine the
 *    true update interval.
 */
@property(assign, nonatomic) NSTimeInterval gyroUpdateInterval __TVOS_PROHIBITED;

/*
 *  gyroAvailable
 *
 *  Discussion:
 *    Determines whether gyro is available.
 */
@property(readonly, nonatomic, getter=isGyroAvailable) BOOL gyroAvailable __TVOS_PROHIBITED;

/*
 *  gyroActive
 *
 *  Discussion:
 *    Determines whether the CMMotionManager is currently providing gyro updates.
 */
@property(readonly, nonatomic, getter=isGyroActive) BOOL gyroActive __TVOS_PROHIBITED;

/*
 *  gyroData
 *
 *  Discussion:
 *    Returns the latest sample of gyro data, or nil if none is available.
 */
@property(readonly, nullable) CMGyroData *gyroData __TVOS_PROHIBITED;

/*
 *  startGyroUpdates
 *
 *  Discussion:
 *    Starts gyro updates with no handler. To receive the latest gyro data
 *    when desired, examine the gyroData property.
 */
- (void)startGyroUpdates __TVOS_PROHIBITED;

/*
 *  startGyroUpdatesToQueue:withHandler:
 *
 *  Discussion:
 *    Starts gyro updates, providing data to the given handler through the given queue.
 *    Note that when the updates are stopped, all operations in the
 *    given NSOperationQueue will be cancelled.

 */
- (void)startGyroUpdatesToQueue:(NSOperationQueue *)queue withHandler:(CMGyroHandler)handler __TVOS_PROHIBITED;

/*
 *  stopGyroUpdates
 *
 *  Discussion:
 *    Stops gyro updates.
 */
- (void)stopGyroUpdates __TVOS_PROHIBITED;

/*
 *  magnetometerUpdateInterval
 *
 *  Discussion:
 *    The interval at which to deliver magnetometer data to the specified
 *    handler once startMagnetometerUpdatesToQueue:withHandler: is called.
 *    The units are in seconds. The value of this property is capped to
 *    certain minimum and maximum values. The maximum value is determined by
 *    the maximum frequency supported by the hardware. If sensitive to the
 *    interval of magnetometer data, an application should always check the
 *    timestamps on the delivered CMMagnetometerData instances to determine the
 *    true update interval.
 */
@property(assign, nonatomic) NSTimeInterval magnetometerUpdateInterval NS_AVAILABLE(NA, 5_0) __TVOS_PROHIBITED;

/*
 *  magnetometerAvailable
 *
 *  Discussion:
 *    Determines whether magetometer is available.
 */
@property(readonly, nonatomic, getter=isMagnetometerAvailable) BOOL magnetometerAvailable NS_AVAILABLE(NA, 5_0) __TVOS_PROHIBITED;

/*
 *  magnetometerActive
 *
 *  Discussion:
 *    Determines whether the CMMotionManager is currently providing magnetometer updates.
 */
@property(readonly, nonatomic, getter=isMagnetometerActive) BOOL magnetometerActive NS_AVAILABLE(NA, 5_0) __TVOS_PROHIBITED;

/*
 *  magnetometerData
 *
 *  Discussion:
 *    Returns the latest sample of magnetometer data, or nil if none is available.
 */
@property(readonly, nullable) CMMagnetometerData *magnetometerData NS_AVAILABLE(NA, 5_0) __TVOS_PROHIBITED;

/*
 *  startMagnetometerUpdates
 *
 *  Discussion:
 *    Starts magnetometer updates with no handler. To receive the latest magnetometer data
 *    when desired, examine the magnetometerData property.
 */
- (void)startMagnetometerUpdates NS_AVAILABLE(NA, 5_0) __TVOS_PROHIBITED;

/*
 *  startMagnetometerUpdatesToQueue:withHandler:
 *
 *  Discussion:
 *    Starts magnetometer updates, providing data to the given handler through the given queue.
 */
- (void)startMagnetometerUpdatesToQueue:(NSOperationQueue *)queue withHandler:(CMMagnetometerHandler)handler NS_AVAILABLE(NA, 5_0) __TVOS_PROHIBITED;

/*
 *  stopMagnetometerUpdates
 *
 *  Discussion:
 *    Stops magnetometer updates.
 */
- (void)stopMagnetometerUpdates NS_AVAILABLE(NA, 5_0) __TVOS_PROHIBITED;

/*
 *  deviceMotionUpdateInterval
 *
 *  Discussion:
 *    The interval at which to deliver device motion data to the specified
 *    handler once startDeviceMotionUpdatesToQueue:withHandler: is called.
 *    The units are in seconds. The value of this property is capped to
 *    certain minimum and maximum values. The maximum value is determined by
 *    the maximum frequency supported by the hardware. If sensitive to the
 *    interval of device motion data, an application should always check the
 *    timestamps on the delivered CMDeviceMotion instances to determine the
 *    true update interval.
 */
@property(assign, nonatomic) NSTimeInterval deviceMotionUpdateInterval __TVOS_PROHIBITED;

/*
 *  availableAttitudeReferenceFrames
 *
 *  Discussion:
 *     Returns a bitmask specifying the available attitude reference frames on the device.
 */
+ (CMAttitudeReferenceFrame)availableAttitudeReferenceFrames NS_AVAILABLE(NA, 5_0) __TVOS_PROHIBITED;

/*
 *  attitudeReferenceFrame
 *
 *  Discussion:
 *    If device motion is active, returns the reference frame currently in-use.
 *    If device motion is not active, returns the default attitude reference frame
 *    for the device. If device motion is not available on the device, the value
 *    is undefined.
 *
 */
@property(readonly, nonatomic) CMAttitudeReferenceFrame attitudeReferenceFrame NS_AVAILABLE(NA, 5_0) __TVOS_PROHIBITED;

/*
 *  deviceMotionAvailable
 *
 *  Discussion:
 *    Determines whether device motion is available using any available attitude reference frame.
 */
@property(readonly, nonatomic, getter=isDeviceMotionAvailable) BOOL deviceMotionAvailable __TVOS_PROHIBITED;

/*
 *  deviceMotionActive
 *
 *  Discussion:
 *    Determines whether the CMMotionManager is currently providing device
 *    motion updates.
 */
@property(readonly, nonatomic, getter=isDeviceMotionActive) BOOL deviceMotionActive __TVOS_PROHIBITED;

/*
 *  deviceMotion
 *
 *  Discussion:
 *    Returns the latest sample of device motion data, or nil if none is available.
 */
@property(readonly, nullable) CMDeviceMotion *deviceMotion __TVOS_PROHIBITED;

/*
 *  startDeviceMotionUpdates
 *
 *  Discussion:
 *    Starts device motion updates with no handler. To receive the latest device motion data
 *    when desired, examine the deviceMotion property. Uses the default reference frame for
 *    the device. Examine CMMotionManager's attitudeReferenceFrame to determine this.
 */
- (void)startDeviceMotionUpdates __TVOS_PROHIBITED;

/*
 *  startDeviceMotionUpdatesToQueue:withHandler:
 *
 *  Discussion:
 *    Starts device motion updates, providing data to the given handler through the given queue.
 *    Uses the default reference frame for the device. Examine CMMotionManager's
 *    attitudeReferenceFrame to determine this.
 *
 */
- (void)startDeviceMotionUpdatesToQueue:(NSOperationQueue *)queue withHandler:(CMDeviceMotionHandler)handler __TVOS_PROHIBITED;

/*
 *  startDeviceMotionUpdatesUsingReferenceFrame:
 *
 *  Discussion:
 *    Starts device motion updates with no handler. To receive the latest device motion data
 *    when desired, examine the deviceMotion property. The specified frame will be used as
 *    reference for the attitude estimates.
 *
 */
- (void)startDeviceMotionUpdatesUsingReferenceFrame:(CMAttitudeReferenceFrame)referenceFrame NS_AVAILABLE(NA, 5_0) __TVOS_PROHIBITED;

/*
 *  startDeviceMotionUpdatesUsingReferenceFrame:toQueue:withHandler
 *
 *  Discussion:
 *    Starts device motion updates, providing data to the given handler through the given queue.
 *    The specified frame will be used as reference for the attitude estimates.
 *
 */
- (void)startDeviceMotionUpdatesUsingReferenceFrame:(CMAttitudeReferenceFrame)referenceFrame toQueue:(NSOperationQueue *)queue withHandler:(CMDeviceMotionHandler)handler NS_AVAILABLE(NA, 5_0) __TVOS_PROHIBITED;

/*
 *  stopDeviceMotionUpdates
 *
 *  Discussion:
 *    Stops device motion updates.
 */
- (void)stopDeviceMotionUpdates __TVOS_PROHIBITED;

/*
 *  showsDeviceMovementDisplay
 *
 *  Discussion:
 *    When the device requires movement, showsDeviceMovementDisplay indicates if the system device
 *    movement display should be shown. Note that when device requires movement,
 *    CMErrorDeviceRequiresMovement is reported once via CMDeviceMotionHandler. By default,
 *    showsDeviceMovementDisplay is NO.
 */
@property(assign, nonatomic) BOOL showsDeviceMovementDisplay NS_AVAILABLE(NA, 5_0) __TVOS_PROHIBITED;

@end

NS_ASSUME_NONNULL_END
