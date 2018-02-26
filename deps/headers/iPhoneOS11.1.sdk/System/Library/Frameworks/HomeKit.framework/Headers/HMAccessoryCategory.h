//
//  HMAccessoryCategory.h
//  HomeKit
//
//  Copyright © 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <HomeKit/HMAccessoryCategoryTypes.h>

NS_ASSUME_NONNULL_BEGIN

/*!
 * @brief This class is used to represent an accessory category.
 */
NS_CLASS_AVAILABLE_IOS(9_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0)
@interface HMAccessoryCategory : NSObject

/*!
 * @brief A type identifier that represents the category.
 */
@property(readonly, copy, nonatomic) NSString *categoryType;

/*!
 * @brief The localized description of the category.
 */
@property(readonly, copy, nonatomic) NSString *localizedDescription;

@end

NS_ASSUME_NONNULL_END
