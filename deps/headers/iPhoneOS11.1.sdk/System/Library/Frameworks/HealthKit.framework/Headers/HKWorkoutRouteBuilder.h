//
//  HKWorkoutRouteBuilder.h
//  HealthKit
//
//  Copyright © 2017 Apple. All rights reserved.
//

#import <HealthKit/HKSeriesBuilder.h>
#import <HealthKit/HKDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class HKHealthStore;
@class HKDevice;
@class HKWorkout;
@class HKWorkoutRoute;
@class CLLocation;

/*!
 @class         HKWorkoutRouteBuilder
 @abstract      An HKWorkoutRouteBuilder is used to generate an HKWorkoutRoute.
 @discussion    This class is intended for generating long-running location data collection such as
                might be associated with a workout. If the discard method is called, collected data will be deleted.
                Calling finishRouteWithWorkout:metadata: will stop and complete the route. If the builder is deleted,
                or the client goes away before calling the finish method, data will be lost.
 */
HK_EXTERN API_AVAILABLE(ios(11.0), watchos(4.0))
@interface HKWorkoutRouteBuilder : HKSeriesBuilder

/*!
 @method        initWithHealthStore:device:
 @abstract      The designated initializer to create an HKWorkoutRouteBuilder.
 @discussion    The HKHealthStore is retained during the life of the object for the saving of the series data and final
                return of the series sample.
 
 @param healthStore Specifies the HKHealthStore object to use for building the series.
 @param device      The optional device represents the HKDevice from which the data is provided.
 */
- (instancetype)initWithHealthStore:(HKHealthStore *)healthStore
                             device:(nullable HKDevice *)device NS_DESIGNATED_INITIALIZER;

/*!
 @method        insertRouteData:completion:
 @abstract      Associate CLLocation with the receiver.
 @discussion    Use this method to asynchronously add one or more CLLocation to the
                series. Note that CLLocation may be inserted in any order but will be
                sorted according to date when the series is finalized.
 
 @param routeData  An array of one or more CLLocation.
 @param completion The completion callback handler returns the status of the save. If the completion handler success is
                   NO, then error is non-nil. An error here is considered fatal and the series builder will be complete.
                   If data was previously saved, then the HKWorkoutRoute may be retrieved by the
                   finishRouteWithMetadata: method.
 */
- (void)insertRouteData:(NSArray<CLLocation *> *)routeData
             completion:(void(^)(BOOL success, NSError * _Nullable error))completion;

/*!
 @method        finishRouteWithWorkout:Metadata:completion:
 @abstract      Method to stop data collection and return the associated HKWorkoutRoute.
 @discussion    Call this method when the route has been completed. The completion handler will return the saved
                HKWorkoutRoute. If no series data was added, then workoutRoute will be nil and an error returned. The
                receiver will be considered invalid afterwards and any further calls to it will result in an error.
 
 @param workout    The HKWorkout object to which the route will be associated. Must be saved to HealthKit
 @param metadata   Optional metadata may be added to associate with the series. Predefined keys are found in
                   HKMetadata.h, or private NSString keys used by the client are allowed. Acceptable metadata value
                   types are NSString, NSDate, NSNumber and HKQuantity
 @param completion The completion callback handler returns the saved HKWorkoutRoute object. If workoutRoute is nil, an
                   error will indicate why the series could not be returned including database inaccessibility during
                   device lock. Subsequent requests for the HKWorkoutRoute can be made through HKSampleQuery or similar
                   queries. workoutRoute cannot be associated to another workout.
 */
- (void)finishRouteWithWorkout:(HKWorkout *)workout
                      metadata:(nullable NSDictionary<NSString *, id> *)metadata
                    completion:(void(^)(HKWorkoutRoute * _Nullable workoutRoute, NSError * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END
