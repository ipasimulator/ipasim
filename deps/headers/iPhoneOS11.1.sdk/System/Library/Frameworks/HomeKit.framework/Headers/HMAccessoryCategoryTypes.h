//
//  HMAccessoryCategoryTypes.h
//  HomeKit
//
//  Copyright © 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <HomeKit/HMDefines.h>

/*!
 * @group Accessory Category Types
 *
 * @brief These constants define the accessory category types supported for HomeKit accessories.
 */

/*!
 * @brief Category type for Other.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeOther NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Security System.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeSecuritySystem NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Bridge.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeBridge NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Door.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeDoor NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Door Lock.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeDoorLock NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Fan.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeFan NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Garage Door Opener.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeGarageDoorOpener NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*
* @brief Category type for IP Camera.
*/
HM_EXTERN NSString * const HMAccessoryCategoryTypeIPCamera NS_AVAILABLE_IOS(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Lightbulb.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeLightbulb NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Outlet.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeOutlet NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Programmable Switch.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeProgrammableSwitch NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Range Extender
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeRangeExtender NS_AVAILABLE_IOS(9_3) __WATCHOS_AVAILABLE(2_2);

/*!
 * @brief Category type for Sensor.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeSensor NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Switch.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeSwitch NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Thermostat.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeThermostat NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Video Doorbell.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeVideoDoorbell NS_AVAILABLE_IOS(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Window.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeWindow NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Window Covering.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeWindowCovering NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Category type for Air Purifier.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeAirPurifier NS_AVAILABLE_IOS(10_2) __WATCHOS_AVAILABLE(3_1_1) __TVOS_AVAILABLE(10_1);

/*!
 * @brief Category type for Air Heater.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeAirHeater NS_AVAILABLE_IOS(10_2) __WATCHOS_AVAILABLE(3_1_1) __TVOS_AVAILABLE(10_1);

/*!
 * @brief Category type for Air Conditioner.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeAirConditioner NS_AVAILABLE_IOS(10_2) __WATCHOS_AVAILABLE(3_1_1) __TVOS_AVAILABLE(10_1);

/*!
 * @brief Category type for Air Humidifier.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeAirHumidifier NS_AVAILABLE_IOS(10_2) __WATCHOS_AVAILABLE(3_1_1) __TVOS_AVAILABLE(10_1);

/*!
 * @brief Category type for Air Dehumidifier.
 */
HM_EXTERN NSString * const HMAccessoryCategoryTypeAirDehumidifier NS_AVAILABLE_IOS(10_2) __WATCHOS_AVAILABLE(3_1_1) __TVOS_AVAILABLE(10_1);
