// HMRoom.h
// HomeKit
//
// Copyright (c) 2013-2015 Apple Inc. All rights reserved.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class HMAccessory;

/*!
 * @brief This class describes a room in the home.
 */
NS_CLASS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0)
@interface HMRoom : NSObject

- (instancetype)init NS_UNAVAILABLE;

/*!
 * @brief Name of the room.
 */
@property(readonly, copy, nonatomic) NSString *name;

/*!
 * @brief Array of HMAccessory objects that correspond to the accessories 
 *        associated with this room.
 */
@property(readonly, copy, nonatomic) NSArray<HMAccessory *> *accessories;

/*!
 * @brief A unique identifier for the room.
 */
@property(readonly, copy, nonatomic) NSUUID *uniqueIdentifier NS_AVAILABLE_IOS(9_0);

/*!
 * @brief This method is used to change the name of the room.
 *
 * @param name New name for the room.
 *
 * @param completion Block that is invoked once the request is processed. 
 *                   The NSError provides more information on the status of the request, error
 *                   will be nil on success.
 */
- (void)updateName:(NSString *)name completionHandler:(void (^)(NSError * __nullable error))completion __WATCHOS_PROHIBITED __TVOS_PROHIBITED;

@end

NS_ASSUME_NONNULL_END
