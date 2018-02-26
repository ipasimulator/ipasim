//
//  HMCharacteristicMetadata.h
//  HomeKit
//
//  Copyright (c) 2014-2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <HomeKit/HMDefines.h>

NS_ASSUME_NONNULL_BEGIN

/*!
 * @brief This class defines the metadata for a characteristic. Metadata provides
 *		  further information about a characteristic’s value, which can be used
 * 		  for presentation purposes.
 */
NS_CLASS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0)
@interface HMCharacteristicMetadata : NSObject

/*!
 * @brief The minimum value for the characteristic if it has a format of "int" or "float".
 */
@property(readonly, nonatomic, nullable) NSNumber *minimumValue;

/*!
 * @brief The maximum value for the characteristic if it has a format of "int" or "float".
 */
@property(readonly, nonatomic, nullable) NSNumber *maximumValue;

/*!
 * @brief Step value for the characteristic that indicates the minimum step value allowed if it has a format of "int" or "float".
 */
@property(readonly, nonatomic, nullable) NSNumber *stepValue;

/*!
 * @brief Max length value for the characteristic that indicates the maximum number of UTF-8 characters allowed if it has a format of "string".
 */
@property(readonly, nonatomic, nullable) NSNumber *maxLength;

/*!
 * @brief The format of the value. Refer to HMCharacteristicMetadataFormat constants for supported units.
 */
@property(readonly, copy, nonatomic, nullable) NSString *format;

/*!
 * @brief The units of the value. Refer to HMCharacteristicMetadataUnits constants for supported units.
 */
@property(readonly, copy, nonatomic, nullable) NSString *units;

/*!
 * @brief Manufacturer provided description for the characteristic to present to the user.
 */
@property(readonly, copy, nonatomic, nullable) NSString *manufacturerDescription;

/*!
 * @brief The subset of valid values supported by the characteristic when the format is unsigned integral type.
 */
@property(readonly, copy, nonatomic, nullable) NSArray<NSNumber *> *validValues NS_AVAILABLE_IOS(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0);;

@end

/*!
 * @group HMCharacteristicMetadataFormat constants
 */

/*!
 * @brief Describes that the value format is boolean.
 *
 * @discussion The value is an NSNumber containing the boolean value.
 */
HM_EXTERN NSString * const HMCharacteristicMetadataFormatBool NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the value format is an integer.
 *
 * @discussion The value is an NSNumber containing a signed 32-bit integer with a range [-2147483648, 2147483647].
 */
HM_EXTERN NSString * const HMCharacteristicMetadataFormatInt NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the value format is a float.
 *
 * @discussion The value is an NSNumber containing a 32-bit float.
 */
HM_EXTERN NSString * const HMCharacteristicMetadataFormatFloat NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the value format is a string.
 *
 * @discussion The value is an NSString.
 */
HM_EXTERN NSString * const HMCharacteristicMetadataFormatString NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the value format is an array.
 *
 * @discussion The value is an NSArray.
 */
HM_EXTERN NSString * const HMCharacteristicMetadataFormatArray NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the value format is a dictionary.
 *
 * @discussion The value is an NSDictionary.
 */
HM_EXTERN NSString * const HMCharacteristicMetadataFormatDictionary NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the value format is an unsigned 8-bit integer.
 *
 * @discussion The value is an NSNumber containing an unsigned 8-bit integer with a range [0, 255].
 */
HM_EXTERN NSString * const HMCharacteristicMetadataFormatUInt8 NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the value format is an unsigned 16-bit integer.
 *
 * @discussion The value is an NSNumber containing an unsigned 16-bit integer with a range [0, 65535].
 */
HM_EXTERN NSString * const HMCharacteristicMetadataFormatUInt16 NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the value format is an unsigned 32-bit integer.
 *
 * @discussion The value is an NSNumber containing an unsigned 32-bit integer with a range [0, 4294967295].
 */
HM_EXTERN NSString * const HMCharacteristicMetadataFormatUInt32 NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the value format is an unsigned 64-bit integer.
 *
 * @discussion The value is an NSNumber containing an unsigned 64-bit integer with a range [0, 18446744073709551615].
 */
HM_EXTERN NSString * const HMCharacteristicMetadataFormatUInt64 NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the value format is a data blob.
 *
 * @discussion The value is an NSData containing the bytes of data.
 */
HM_EXTERN NSString * const HMCharacteristicMetadataFormatData NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the value format is a TLV8.
 *
 * @discussion The value is an NSData containing a set of one or more TLV8's, which are packed type-length-value items with an 8-bit type, 8-bit length, and N-byte value.
 */
HM_EXTERN NSString * const HMCharacteristicMetadataFormatTLV8 NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);


/*!
 * @group HMCharacteristicMetadataUnits constants
 */

/*!
 * @brief Describes that the unit of the characteristic is in Celsius.
 */
HM_EXTERN NSString * const HMCharacteristicMetadataUnitsCelsius NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the unit of the characteristic is in Fahrenheit.
 */
HM_EXTERN NSString * const HMCharacteristicMetadataUnitsFahrenheit NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the unit of the characteristic is a percentage.
 */
HM_EXTERN NSString * const HMCharacteristicMetadataUnitsPercentage NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the unit of the characteristic is arc degree.
 */
HM_EXTERN NSString * const HMCharacteristicMetadataUnitsArcDegree NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the unit of the characteristic is seconds.
 */
HM_EXTERN NSString * const HMCharacteristicMetadataUnitsSeconds NS_AVAILABLE_IOS(8_3) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the unit of the characteristic is Lux (illuminance).
 */
HM_EXTERN NSString * const HMCharacteristicMetadataUnitsLux NS_AVAILABLE_IOS(9_3) __WATCHOS_AVAILABLE(2_2) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the unit of the characteristic is parts per million.
 */
HM_EXTERN NSString * const HMCharacteristicMetadataUnitsPartsPerMillion __IOS_AVAILABLE(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Describes that the unit of the characteristic is micrograms per cubic meter.
 */
HM_EXTERN NSString * const HMCharacteristicMetadataUnitsMicrogramsPerCubicMeter __IOS_AVAILABLE(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0);


NS_ASSUME_NONNULL_END
