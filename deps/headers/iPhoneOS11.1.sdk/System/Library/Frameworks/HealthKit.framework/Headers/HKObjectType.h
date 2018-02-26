//
//  HKObjectType.h
//  HealthKit
//
//  Copyright (c) 2013-2017 Apple Inc. All rights reserved.
//

#import <HealthKit/HKDefines.h>
#import <HealthKit/HKTypeIdentifiers.h>
#import <HealthKit/HKQuantityAggregationStyle.h>

NS_ASSUME_NONNULL_BEGIN

@class HKActivitySummaryType;
@class HKCategoryType;
@class HKCharacteristicType;
@class HKCorrelationType;
@class HKDocumentType;
@class HKQuantityType;
@class HKSeriesType;
@class HKUnit;
@class HKWorkoutType;

/*!
 @class         HKObjectType
 @abstract      An abstract class representing a type of object that can be stored by HealthKit.
 */
HK_EXTERN API_AVAILABLE(ios(8.0), watchos(2.0))
@interface HKObjectType : NSObject <NSSecureCoding, NSCopying>

/*!
 @property      identifier
 @abstract      A unique string identifying a type of health object.
 @discussion    See HKTypeIdentifiers.h for possible values.
 */
@property (readonly, strong) NSString *identifier;

- (instancetype)init NS_UNAVAILABLE;

+ (nullable HKQuantityType *)quantityTypeForIdentifier:(HKQuantityTypeIdentifier)identifier;
+ (nullable HKCategoryType *)categoryTypeForIdentifier:(HKCategoryTypeIdentifier)identifier;
+ (nullable HKCharacteristicType *)characteristicTypeForIdentifier:(HKCharacteristicTypeIdentifier)identifier;
+ (nullable HKCorrelationType *)correlationTypeForIdentifier:(HKCorrelationTypeIdentifier)identifier;
+ (nullable HKDocumentType *)documentTypeForIdentifier:(HKDocumentTypeIdentifier)identifier API_AVAILABLE(ios(10.0), watchos(3.0));
+ (nullable HKSeriesType *)seriesTypeForIdentifier:(NSString *)identifier API_AVAILABLE(ios(11.0), watchos(4.0));
+ (HKWorkoutType *)workoutType;
+ (HKActivitySummaryType *)activitySummaryType API_AVAILABLE(ios(9.3), watchos(2.2));

@end

/*!
 @class         HKCharacteristicType
 @abstract      Represents a type of object that describes a characteristic of the user (such as date of birth).
 */
HK_EXTERN API_AVAILABLE(ios(8.0), watchos(2.0))
@interface HKCharacteristicType : HKObjectType
@end

/*!
 @class         HKSampleType
 @abstract      Represents a type of HKSample.
 */
HK_EXTERN API_AVAILABLE(ios(8.0), watchos(2.0))
@interface HKSampleType : HKObjectType
@end

/*!
 @class         HKCategoryType
 @abstract      Represent a type of HKCategorySample.
 */
HK_EXTERN API_AVAILABLE(ios(8.0), watchos(2.0))
@interface HKCategoryType : HKSampleType
@end

/*!
 @class         HKCorrelationType
 @abstract      Represents a type of HKCorrelation
 */
HK_EXTERN API_AVAILABLE(ios(8.0), watchos(2.0))
@interface HKCorrelationType : HKSampleType
@end

/*!
 @class         HKDocumentType
 @abstract      Represents a type of HKDocument.
 */
HK_EXTERN API_AVAILABLE(ios(10.0))
@interface HKDocumentType : HKSampleType
@end

/*!
 @class         HKQuantityType
 @abstract      Represents types of HKQuantitySamples.
 */
HK_EXTERN API_AVAILABLE(ios(8.0), watchos(2.0))
@interface HKQuantityType : HKSampleType

@property (readonly) HKQuantityAggregationStyle aggregationStyle;

/*!
 @method        isCompatibleWithUnit:
 @abstract      Returns YES if the type of HKQuantitySample represented by the receiver can be created with quantities 
                of the given unit.
 */
- (BOOL)isCompatibleWithUnit:(HKUnit *)unit;

@end

/*!
 @class         HKWorkoutType
 @abstract      Represents a workout or exercise
 */
HK_EXTERN API_AVAILABLE(ios(8.0), watchos(2.0))
@interface HKWorkoutType : HKSampleType
@end

/*!
 @class         HKSeriesType
 @abstract      Represents a type of HKSeriesSample
 */
HK_EXTERN API_AVAILABLE(ios(11.0), watchos(4.0))
@interface HKSeriesType : HKSampleType

+ (instancetype)workoutRouteType;

@end

/*!
 @class         HKActivitySummaryType
 @abstract      Represents an HKActivitySummary
 */
HK_EXTERN API_AVAILABLE(ios(9.3), watchos(2.2))
@interface HKActivitySummaryType : HKObjectType
@end


NS_ASSUME_NONNULL_END
