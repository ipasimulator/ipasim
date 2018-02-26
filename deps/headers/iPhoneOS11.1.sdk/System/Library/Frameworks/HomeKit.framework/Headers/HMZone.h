// HMZone.h
// HomeKit
//
// Copyright (c) 2013-2015 Apple Inc. All rights reserved.

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class HMRoom;

/*!
 * @brief Used to describe a collection of HMRoom objects
 *
 * @discussion This class is used to group a collection of rooms.
 *             This allows for association of a set of rooms into a group.
 *             Eg. "Living Room" and "Kitchen" rooms can be grouped together
 *             in the "Downstairs" zone.
 */
NS_CLASS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0)
@interface HMZone : NSObject

- (instancetype)init NS_UNAVAILABLE;

/*!
 * @brief Name of the zone.
 */
@property(readonly, copy, nonatomic) NSString *name;

/*!
 * @brief Array of HMRoom objects that correspond to the rooms contained in this zone.
 */
@property(readonly, copy, nonatomic) NSArray<HMRoom *> *rooms;

/*!
 * @brief A unique identifier for the zone.
 */
@property(readonly, copy, nonatomic) NSUUID *uniqueIdentifier NS_AVAILABLE_IOS(9_0);

/*!
 * @brief This method is used to change the name of the zone.
 *
 * @param name New name for the zone.
 *
 * @param completion Block that is invoked once the request is processed. 
 *                   The NSError provides more information on the status of the request, error
 *                   will be nil on success.
 */
- (void)updateName:(NSString *)name completionHandler:(void (^)(NSError * __nullable error))completion __WATCHOS_PROHIBITED __TVOS_PROHIBITED;

/*!
 * @brief Adds a room to a zone.
 *
 * @discussion Both the room and the zone should be part of the home.  A room can be added to multiple
 *             zones, e.g., a room "Kitchen" can be added to "Downstairs" as well as "Outdoor" zones.
 *
 * @param room Room to add to this zone.
 *
 * @param completion Block that is invoked once the request is processed. 
 *                   The NSError provides more information on the status of the request, error
 *                   will be nil on success.
 */
- (void)addRoom:(HMRoom *)room completionHandler:(void (^)(NSError * __nullable error))completion __WATCHOS_PROHIBITED __TVOS_PROHIBITED;

/*!
 * @brief Removes a room from the zone.
 *
 * @param room Room to remove from this zone.
 *
 * @param completion Block that is invoked once the request is processed. 
 *                   The NSError provides more information on the status of the request, error
 *                   will be nil on success.
 */
- (void)removeRoom:(HMRoom *)room completionHandler:(void (^)(NSError * __nullable error))completion __WATCHOS_PROHIBITED __TVOS_PROHIBITED;

@end

NS_ASSUME_NONNULL_END
