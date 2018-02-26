//  HMAction.h
//  HomeKit
//
//  Copyright (c) 2014-2015 Apple Inc. All rights reserved.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/*!
 * @brief This class is used to represent a generic action.
 */
NS_CLASS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0)
@interface HMAction : NSObject

/*!
 * @brief A unique identifier for the action.
 */
@property(readonly, copy, nonatomic) NSUUID *uniqueIdentifier NS_AVAILABLE_IOS(9_0);

@end

NS_ASSUME_NONNULL_END
