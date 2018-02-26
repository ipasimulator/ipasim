//
//  HKWorkoutSession.h
//  HealthKit
//
//  Copyright (c) 2015 Apple. All rights reserved.
//

#import <HealthKit/HKWorkout.h>
#import <HealthKit/HKMetadata.h>

NS_ASSUME_NONNULL_BEGIN

@protocol HKWorkoutSessionDelegate;

/*!
 @enum          HKWorkoutSessionState
 @abstract      This enumerated type is used to represent the state of a workout session.
 */
typedef NS_ENUM(NSInteger, HKWorkoutSessionState) {
    HKWorkoutSessionStateNotStarted = 1,
    HKWorkoutSessionStateRunning,
    HKWorkoutSessionStateEnded,
    HKWorkoutSessionStatePaused API_AVAILABLE(watchos(3.0)),
} API_AVAILABLE(watchos(2.0)) API_UNAVAILABLE(ios);


/*!
 @enum          HKWorkoutSessionLocationType
 @abstract      This enumerated type is used to represent the location type of a workout session.
 @discussion    This value represents whether a workout is performed indoors or outdoors.
 */
typedef NS_ENUM(NSInteger, HKWorkoutSessionLocationType) {
    HKWorkoutSessionLocationTypeUnknown = 1,
    HKWorkoutSessionLocationTypeIndoor,
    HKWorkoutSessionLocationTypeOutdoor,
} API_AVAILABLE(ios(10.0), watchos(2.0));


/*!
 @class         HKWorkoutConfiguration
 @abstract      An HKWorkoutConfiguration is an object that can be used to describe the a workout activity.
 */
HK_EXTERN API_AVAILABLE(ios(10.0), watchos(3.0))
@interface HKWorkoutConfiguration : NSObject <NSCopying, NSSecureCoding>

/*!
 @property      activityType
 @abstract      Indicates the type of workout for the configuration.
 */
@property (assign) HKWorkoutActivityType activityType;

/*!
 @property      locationType
 @abstract      Indicates the type of location (indoors vs. outdoors) for the configuration.
 */
@property (assign) HKWorkoutSessionLocationType locationType;

/*!
 @property      swimmingLocationType
 @abstract      Indicates the type of swimming location (pool vs. open water) where the workout will take place.
 */
@property (assign) HKWorkoutSwimmingLocationType swimmingLocationType;

/*!
 @property      lapLength
 @abstract      Indicates the length of the pool, when the workout location type is pool.
 @discussion    This metric represents the length of the pool where the workout takes place. It should be a quantity with
                a unit representing length.
 */
@property (copy, nullable) HKQuantity *lapLength;

@end


/*!
 @class         HKWorkoutSession
 @abstract      An HKWorkoutSession is an object describing the properties of a workout activity session.
 */
HK_EXTERN API_AVAILABLE(watchos(2.0)) API_UNAVAILABLE(ios)
@interface HKWorkoutSession : NSObject <NSSecureCoding>

/*!
 @property      activityType
 @abstract      Indicates the type of workout that will be performed during the session.
 */
@property (readonly) HKWorkoutActivityType activityType API_DEPRECATED_WITH_REPLACEMENT("workoutConfiguration", watchos(2.0, 3.0));

/*!
 @property      locationType
 @abstract      Indicates the type of location (indoors vs. outdoors) where the workout will take place.
 @discussion    Knowing the location type allows for more accurate measurements and better performance.
 */
@property (readonly) HKWorkoutSessionLocationType locationType API_DEPRECATED_WITH_REPLACEMENT("workoutConfiguration", watchos(2.0, 3.0));

/*!
 @property      workoutConfiguration
 @abstract      The configuration object describing the workout.
 @discussion    This returns a copy of the configuration passed when creating the HKWorkoutSession. Changes made to
                the returned object have no impact on the HKWorkoutSession.
 */
@property (readonly, copy) HKWorkoutConfiguration *workoutConfiguration API_AVAILABLE(watchos(3.0));

/*!
 @property      delegate
 @abstract      The session delegate, which receives
 @discussion    The session delegate object is the one implementing the methods that get called when the session
                state changes or a failure occurs in the session.
 */
@property (weak, nullable) id<HKWorkoutSessionDelegate> delegate;

/*!
 @property      state
 @abstract      Indicates the current state of the workout session.
 @discussion    Each time this value is updated, the delegate method workoutSession:didChangeToState:fromState:date:
                will be called.
 */
@property (readonly) HKWorkoutSessionState state;

/*!
 @property      startDate
 @abstract      Indicates the date when the workout session started running.
 @discussion    This value is nil when a workout session is initialized. It is set when the workout session state
                changes to HKWorkoutSessionStateRunning.
 */
@property (readonly, nullable) NSDate *startDate;

/*!
 @property      endDate
 @abstract      Indicates the date when the workout session ended.
 @discussion    This value is nil when a workout session is initialized. It is set when the workout session state
                changes to HKWorkoutSessionStateEnded.
 */
@property (readonly, nullable) NSDate *endDate;

/*!
 @method        initWithActivityType:locationType:

 @param         activityType    The activity type of the workout session.
 @param         locationType    The type of location where the workout will be performed.
 */
- (instancetype)initWithActivityType:(HKWorkoutActivityType)activityType
                        locationType:(HKWorkoutSessionLocationType)locationType API_DEPRECATED_WITH_REPLACEMENT("initWithConfiguration:error:", watchos(2.0, 3.0));

/*!
 @method        initWithConfiguration:

 @param         workoutConfiguration Configuration object describing the various properties of a workout.
 @param         error                If the configuration does not specify valid configuration properties, an
                                     an NSError describing the error is set and nil is returned.
 */
- (nullable instancetype)initWithConfiguration:(HKWorkoutConfiguration *)workoutConfiguration error:(NSError **)error API_AVAILABLE(watchos(3.0));

- (instancetype)init NS_UNAVAILABLE;

@end


/*!
 @enum          HKWorkoutSessionStateDelegate
 @abstract      This protocol should be implemented to be notified when a workout session's state changes.
 @discussion    The methods on this protocol are called on an anonymous serial background queue.
 */
API_AVAILABLE(watchos(2.0)) API_UNAVAILABLE(ios)
@protocol HKWorkoutSessionDelegate <NSObject>

/*!
 @method        workoutSession:didChangeToState:fromState:date:
 @abstract      This method is called when a workout session transitions to a new state.
 @discussion    The date is provided to indicate when the state change actually happened.  If your application is
                suspended then the delegate will receive this call once the application resumes, which may be much later
                than when the original state change ocurred.
 */
- (void)workoutSession:(HKWorkoutSession *)workoutSession
      didChangeToState:(HKWorkoutSessionState)toState
             fromState:(HKWorkoutSessionState)fromState
                  date:(NSDate *)date;

/*!
 @method        workoutSession:didFailWithError:
 @abstract      This method is called when an error occurs that stops a workout session.
 @discussion    When the state of the workout session changes due to an error occurring, this method is always called
                before workoutSession:didChangeToState:fromState:date:.
 */
- (void)workoutSession:(HKWorkoutSession *)workoutSession didFailWithError:(NSError *)error;

@optional

/*!
 @method        workoutSession:didGenerateEvent:
 @abstract      This method is called whenever the system generates a workout event.
 @discussion    Whenever a workout event is generated, such as pause or resume detection, the event will be passed
                to the session delegate via this method. Clients may save the generated events to use when creating an
                HKWorkout object.
 */
- (void)workoutSession:(HKWorkoutSession *)workoutSession didGenerateEvent:(HKWorkoutEvent *)event API_AVAILABLE(ios(10.0), watchos(3.0));

@end

NS_ASSUME_NONNULL_END
