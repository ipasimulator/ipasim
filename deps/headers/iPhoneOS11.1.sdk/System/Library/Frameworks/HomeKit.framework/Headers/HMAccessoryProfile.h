//
//  HMAccessoryProfile.h
//  HomeKit
//
//  Copyright © 2015-2016 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@class HMAccessory;
@class HMService;

NS_ASSUME_NONNULL_BEGIN

/*!
 * @abstract Represents a profile implemented by an accessory.
 */
__IOS_AVAILABLE(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0)
@interface HMAccessoryProfile : NSObject

- (instancetype)init NS_UNAVAILABLE;

/*!
 * @brief A unique identifier for the profile.
 */
@property(readonly, copy, nonatomic) NSUUID *uniqueIdentifier;

/*!
 * @brief Collection of services representing the profile.
 */
@property(readonly, strong, nonatomic) NSArray<HMService *> *services;

/*!
 * @brief Accessory implementing the profile.
 */
@property(readonly, weak, nonatomic) HMAccessory *accessory;

@end

NS_ASSUME_NONNULL_END
