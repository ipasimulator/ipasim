//  HMServiceTypes.h
//  HomeKit
//
//  Copyright © 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <HomeKit/HMDefines.h>

/*!
 * @group Accessory Service Types
 *
 * @brief These constants define the service types supported by the HomeKit Accessory Profile for HomeKit based accessories.
 */

NS_ASSUME_NONNULL_BEGIN

/*!
 * @brief Service type for lightbulb.
 */
HM_EXTERN NSString * const HMServiceTypeLightbulb NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for switch.
 */
HM_EXTERN NSString * const HMServiceTypeSwitch NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for thermostat.
 */
HM_EXTERN NSString * const HMServiceTypeThermostat NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for garage door opener.
 */
HM_EXTERN NSString * const HMServiceTypeGarageDoorOpener NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for accessory information.
 */
HM_EXTERN NSString * const HMServiceTypeAccessoryInformation NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for fan.
 */
HM_EXTERN NSString * const HMServiceTypeFan NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for outlet.
 */
HM_EXTERN NSString * const HMServiceTypeOutlet NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for lock mechanism.
 */
HM_EXTERN NSString * const HMServiceTypeLockMechanism NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for lock management.
 */
HM_EXTERN NSString * const HMServiceTypeLockManagement NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for air quality sensor.
 */
HM_EXTERN NSString * const HMServiceTypeAirQualitySensor NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for battery.
 */
HM_EXTERN NSString * const HMServiceTypeBattery NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for carbon dioxide sensor.
 */
HM_EXTERN NSString * const HMServiceTypeCarbonDioxideSensor NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for carbon monoxide sensor.
 */
HM_EXTERN NSString * const HMServiceTypeCarbonMonoxideSensor NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for contact sensor.
 */
HM_EXTERN NSString * const HMServiceTypeContactSensor NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for door.
 */
HM_EXTERN NSString * const HMServiceTypeDoor NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for doorbell.
 */
HM_EXTERN NSString * const HMServiceTypeDoorbell NS_AVAILABLE_IOS(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for humidity sensor.
 */
HM_EXTERN NSString * const HMServiceTypeHumiditySensor NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for leak sensor.
 */
HM_EXTERN NSString * const HMServiceTypeLeakSensor NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for light sensor.
 */
HM_EXTERN NSString * const HMServiceTypeLightSensor NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for motion sensor.
 */
HM_EXTERN NSString * const HMServiceTypeMotionSensor NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for occupancy sensor.
 */
HM_EXTERN NSString * const HMServiceTypeOccupancySensor NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for security system.
 */
HM_EXTERN NSString * const HMServiceTypeSecuritySystem NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for stateful programmable switch.
 */
HM_EXTERN NSString * const HMServiceTypeStatefulProgrammableSwitch NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for stateless programmable switch.
 */
HM_EXTERN NSString * const HMServiceTypeStatelessProgrammableSwitch NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for smoke sensor.
 */
HM_EXTERN NSString * const HMServiceTypeSmokeSensor NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for temperature sensor.
 */
HM_EXTERN NSString * const HMServiceTypeTemperatureSensor NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for window.
 */
HM_EXTERN NSString * const HMServiceTypeWindow NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for window covering.
 */
HM_EXTERN NSString * const HMServiceTypeWindowCovering NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for stream management.
 */
HM_EXTERN NSString * const HMServiceTypeCameraRTPStreamManagement NS_AVAILABLE_IOS(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for camera control.
 */
HM_EXTERN NSString * const HMServiceTypeCameraControl NS_AVAILABLE_IOS(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for microphone.
 */
HM_EXTERN NSString * const HMServiceTypeMicrophone NS_AVAILABLE_IOS(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for speaker.
 */
HM_EXTERN NSString * const HMServiceTypeSpeaker NS_AVAILABLE_IOS(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Service type for air purifier.
 */
HM_EXTERN NSString * const HMServiceTypeAirPurifier NS_AVAILABLE_IOS(10_2) __WATCHOS_AVAILABLE(3_1_1) __TVOS_AVAILABLE(10_1);

/*!
 * @brief Service type for ventilation fan.
 */
HM_EXTERN NSString * const HMServiceTypeVentilationFan NS_AVAILABLE_IOS(10_2) __WATCHOS_AVAILABLE(3_1_1) __TVOS_AVAILABLE(10_1);

/*!
 * @brief Service type for filter maintenance.
 */
HM_EXTERN NSString * const HMServiceTypeFilterMaintenance NS_AVAILABLE_IOS(10_2) __WATCHOS_AVAILABLE(3_1_1) __TVOS_AVAILABLE(10_1);

/*!
 * @brief Service type for heater/cooler.
 */
HM_EXTERN NSString * const HMServiceTypeHeaterCooler NS_AVAILABLE_IOS(10_2) __WATCHOS_AVAILABLE(3_1_1) __TVOS_AVAILABLE(10_1);

/*!
 * @brief Service type for humidifier/dehumidifier.
 */
HM_EXTERN NSString * const HMServiceTypeHumidifierDehumidifier NS_AVAILABLE_IOS(10_2) __WATCHOS_AVAILABLE(3_1_1) __TVOS_AVAILABLE(10_1);

/*!
 * @brief Service type for slats.
 */
HM_EXTERN NSString * const HMServiceTypeSlats NS_AVAILABLE_IOS(10_2) __WATCHOS_AVAILABLE(3_1_1) __TVOS_AVAILABLE(10_1);

/*!
 * @brief Service type for label namespace when accessory supports multiple services of the same type.
 */
HM_EXTERN NSString * const HMServiceTypeLabel NS_AVAILABLE_IOS(10_3) __WATCHOS_AVAILABLE(3_2) __TVOS_AVAILABLE(10_2);

NS_ASSUME_NONNULL_END
