//
//  HMSignificantEvents.h
//  HomeKit
//
//  Copyright © 2016 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <HomeKit/HMDefines.h>

NS_ASSUME_NONNULL_BEGIN

/*!
 * @brief Type corresponding to significant events.
 */
typedef NSString * HMSignificantEvent NS_EXTENSIBLE_STRING_ENUM;

/*!
 * @brief Event corresponding to sunrise
 */
HM_EXTERN HMSignificantEvent const HMSignificantEventSunrise NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

/*!
 * @brief Event corresponding to sunset
 */
HM_EXTERN HMSignificantEvent const HMSignificantEventSunset NS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0);

NS_ASSUME_NONNULL_END


