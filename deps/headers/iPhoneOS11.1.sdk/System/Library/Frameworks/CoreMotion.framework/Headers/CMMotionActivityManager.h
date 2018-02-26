/*
 *  CMMotionActivityManager.h
 *  CoreMotion
 *
 *  Copyright (c) 2013 Apple Inc. All rights reserved.
 */

#import <Foundation/Foundation.h>
#import <CoreMotion/CMMotionActivity.h>
#import <CoreMotion/CMAvailability.h>
#import <CoreMotion/CMAuthorization.h>

NS_ASSUME_NONNULL_BEGIN

/*
 *  CMMotionActivityHandler
 *
 *  Discussion:
 *    Typedef of block to be invoked when the device's activity is updated.
 */
typedef void (^CMMotionActivityHandler)(CMMotionActivity * __nullable activity) NS_AVAILABLE(NA,7_0) __TVOS_PROHIBITED;

/*
 *  CMMotionActivityQueryHandler
 *
 *  Discussion:
 *    Typedef of block to be invoked when the historical activity query is
 *    completed.  The array is an array of CMMotionActivity objects.
 */
typedef void (^CMMotionActivityQueryHandler)(NSArray<CMMotionActivity *> * __nullable activities, NSError * __nullable error) NS_AVAILABLE(NA,7_0) __TVOS_PROHIBITED;

/*
 *   CMMotionActivityManager
 *
 *   Discussion:
 *      CMMotionActivityManager allows access to the activity of the device.
 *      Activities can be retrieved in one of two ways:
 *
 *      1. Via a query specifying a time range from which an array of
 *      activities will be returned.
 *
 *      2. By providing a queue and a block to startActivityUpdatesToQueue:withHandler:
 *      which will provide live activity updates to a running application.
 */
NS_CLASS_AVAILABLE(NA,7_0) __TVOS_PROHIBITED
@interface CMMotionActivityManager : NSObject

/*
 *  isActivityAvailable
 *
 *  Discussion:
 *      Determines whether activity estimation is available.
 */
+ (BOOL)isActivityAvailable;

/*
 *  authorizationStatus
 *
 *  Discussion:
 *      Returns the current authorization status for activity.
 */
+ (CMAuthorizationStatus)authorizationStatus NS_AVAILABLE(NA, 11_0) __WATCHOS_AVAILABLE(4_0);

/*
 * queryActivityStartingFrom:to:toQueue:withHandler:
 *
 * Discussion:
 *      Queries for activity transitions that happened during the given time
 *      range.  The date range must be in the past.  Data is only available
 *      for the last seven days.  The result is returned to the handler/queue
 *      specified.
 *
 *      The first activity returned may have a startDate before start. This
 *      activity represents what the state was at the start time.
 *
 */
- (void)queryActivityStartingFromDate:(NSDate *)start
                               toDate:(NSDate *)end
                              toQueue:(NSOperationQueue *)queue
                          withHandler:(CMMotionActivityQueryHandler)handler;

/*
 *  startActivityUpdatesToQueue:withHandler
 *
 *  Discussion:
 *      Start activity updates, providing data to the given handler through
 *      the given queue.  An update with the current activity will arrive
 *      first.  Then when the activity state changes the handler will be
 *      called with the new activity.
 *
 *      You can only have one handler installed at a time, calling
 *      startActivityUpdatesToQueue:withHandler: replaces the current
 *      handler.
 *
 *      Updates are not delivered while the application is suspended, the
 *      application may use
 *      queryActivityStartingFromDate:toDate:toQueue:withHandler: to get
 *      activities from the time when the application was suspended.
 */
- (void)startActivityUpdatesToQueue:(NSOperationQueue *)queue
                        withHandler:(CMMotionActivityHandler)handler;

/*
 *  stopActivityUpdates
 *
 *  Discussion:
 *      Stop delivering live updates.
 */
- (void)stopActivityUpdates;

@end

NS_ASSUME_NONNULL_END
