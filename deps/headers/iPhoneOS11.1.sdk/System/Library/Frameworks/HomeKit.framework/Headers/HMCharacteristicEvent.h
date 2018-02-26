// HMCharacteristicEvent.h
// HomeKit
//
// Copyright (c) 2015 Apple Inc. All rights reserved.

#import <Foundation/Foundation.h>
#import <HomeKit/HMEvent.h>

NS_ASSUME_NONNULL_BEGIN

@class HMCharacteristic;

/*!
 * @brief This class represents an event that is evaluated based on the value of a characteristic
 *        set to a particular value.
 */
NS_CLASS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0)
@interface HMCharacteristicEvent<TriggerValueType : id<NSCopying>> : HMEvent <NSCopying, NSMutableCopying>

- (instancetype)init NS_UNAVAILABLE;

/*!
 * @brief Initializes a new characteristic event object
 *
 * @param characteristic The characteristic bound to the event. The characteristic must 
 *                       support notification. An exception will be thrown otherwise.
 *
 * @param triggerValue The value of the characteristic that triggers the event. 
 *                     Specifying nil as the trigger value corresponds to any change in the value of the
 *                     characteristic.
 *
 * @return Instance object representing the characteristic event.
 */
- (instancetype)initWithCharacteristic:(HMCharacteristic *)characteristic
                          triggerValue:(nullable TriggerValueType)triggerValue __WATCHOS_PROHIBITED __TVOS_PROHIBITED;

/*!
 * @brief The characteristic associated with the event.
 */
@property(readonly, strong, nonatomic) HMCharacteristic *characteristic;

/*!
 * @brief The value of the characteristic that triggers the event.
 *        A value of nil corresponds to any change in the value of the characteristic.
 */
@property(readonly, copy, nonatomic, nullable) TriggerValueType triggerValue;

/*!
 * @brief This method is used to change trigger value for the characteristic.
 *
 * @param triggerValue New trigger value for the characteristic.
 *                     Specifying nil as the trigger value corresponds to any change in the value of the
 *                     characteristic.
 *
 * @param completion Block that is invoked once the request is processed. 
 *                   The NSError provides more information on the status of the request, error
 *                   will be nil on success.
 */
- (void)updateTriggerValue:(nullable TriggerValueType)triggerValue completionHandler:(void (^)(NSError * __nullable error))completion NS_DEPRECATED_IOS(9_0, 11_0) __WATCHOS_PROHIBITED __TVOS_PROHIBITED;

@end




/*!
 * @brief This class represents an event that is evaluated based on the value of a characteristic
 *        set to a particular value.
 */
API_AVAILABLE(ios(11.0), watchos(4.0), tvos(11.0))
@interface HMMutableCharacteristicEvent<TriggerValueType : id<NSCopying>> : HMCharacteristicEvent

- (instancetype)init NS_UNAVAILABLE;

/*!
 * @brief The characteristic associated with the event.
 */
@property(readwrite, strong, nonatomic) HMCharacteristic *characteristic;

/*!
 * @brief The value of the characteristic that triggers the event.
 *        A value of nil corresponds to any change in the value of the characteristic.
 */
@property(readwrite, copy, nonatomic, nullable) TriggerValueType triggerValue;

@end

NS_ASSUME_NONNULL_END
