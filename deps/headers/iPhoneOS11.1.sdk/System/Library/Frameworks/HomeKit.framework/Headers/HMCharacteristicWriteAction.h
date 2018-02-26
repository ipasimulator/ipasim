// HMCharacteristicWriteAction.h
// HomeKit
//
// Copyright (c) 2014-2015 Apple Inc. All rights reserved.

#import <Foundation/Foundation.h>
#import <HomeKit/HMAction.h>

NS_ASSUME_NONNULL_BEGIN

@class HMCharacteristic;

/*!
 * @brief This class is used to represent an entry in an action set that writes a specific
 *        value to a characteristic.
 */
NS_CLASS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0)
@interface HMCharacteristicWriteAction<TargetValueType : id<NSCopying>> : HMAction

- (instancetype)init NS_UNAVAILABLE;

/*!
 * @brief Initializer method that ties the action to a particular characteristic.
 *
 * @param characteristic The characteristic bound to the action.
 *
 * @param targetValue The target value for the characteristic.
 *
 * @return Instance object representing the characteristic write action.
 */
- (instancetype)initWithCharacteristic:(HMCharacteristic *)characteristic
                           targetValue:(TargetValueType)targetValue NS_DESIGNATED_INITIALIZER __WATCHOS_PROHIBITED __TVOS_PROHIBITED;

/*!
 * @brief The characteristic associated with the action.
 */
@property(readonly, strong, nonatomic) HMCharacteristic* characteristic;

/*!
 * @brief The target value for the action.
 */
@property(readonly, copy, nonatomic) TargetValueType targetValue;

/*!
 * @brief This method is used to change target value for the characteristic.
 *
 * @param targetValue New target value for the characteristic.
 *
 * @param completion Block that is invoked once the request is processed. 
 *                   The NSError provides more information on the status of the request, error
 *                   will be nil on success.
 */
- (void)updateTargetValue:(TargetValueType)targetValue completionHandler:(void (^)(NSError * __nullable error))completion __WATCHOS_PROHIBITED __TVOS_PROHIBITED;

@end

NS_ASSUME_NONNULL_END
