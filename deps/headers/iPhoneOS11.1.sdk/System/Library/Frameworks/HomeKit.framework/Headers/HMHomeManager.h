// HMHomeManager.h
// HomeKit
//
// Copyright (c) 2013-2015 Apple Inc. All rights reserved.

#import <Foundation/Foundation.h>
#import <HomeKit/HMDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class HMHome;

@protocol HMHomeManagerDelegate;

/*!
 * @brief Manages collection of one or more homes.
 *
 * @discussion This class is responsible for managing a collection of homes. 
 */
NS_CLASS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0)
@interface HMHomeManager : NSObject

/*!
 * @brief Delegate that receives updates on the collection of homes.
 */
@property(weak, nonatomic, nullable) id<HMHomeManagerDelegate> delegate;

/*!
 * @brief The primary home for this collection.
 */
@property(readonly, strong, nonatomic, nullable) HMHome *primaryHome;

/*!
 * @brief Array of HMHome objects that represents the homes associated with the home manager.
 *
 * @discussion When a new home manager is created, this array is inialized as an empty array. It is
 *             not guaranteed to be filled with the list of homes, represented as HMHome objects,
 *             until the homeManagerDidUpdateHomes: delegate method has been invoked.
 */
@property(readonly, copy, nonatomic) NSArray<HMHome *> *homes;

/*!
 * @brief This method is used to change the primary home.
 *
 * @param home New primary home.
 *
 * @param completion Block that is invoked once the request is processed. 
 *                   The NSError provides more information on the status of the request, error
 *                   will be nil on success.
 */
- (void)updatePrimaryHome:(HMHome *)home completionHandler:(void (^)(NSError * __nullable error))completion __WATCHOS_PROHIBITED __TVOS_PROHIBITED;

/*!
 * @brief Adds a new home to the collection.
 *
 * @param homeName Name of the  home to create and add to the collection.
 *
 * @param completion Block that is invoked once the request is processed. 
 *                   The NSError provides more information on the status of the request, error
 *                   will be nil on success.
 *
 */
- (void)addHomeWithName:(NSString *)homeName completionHandler:(void (^)(HMHome * __nullable home, NSError * __nullable error))completion __WATCHOS_PROHIBITED __TVOS_PROHIBITED;

/*!
 * @brief Removes an existing home from the collection.
 *
 * @param home Home object that needs to be removed from the collection.
 *
 * @param completion Block that is invoked once the request is processed. 
 *                   The NSError provides more information on the status of the request, error
 *                   will be nil on success.
 */
- (void)removeHome:(HMHome *)home completionHandler:(void (^)(NSError * __nullable error))completion __WATCHOS_PROHIBITED __TVOS_PROHIBITED;

@end

/*!
 * @brief This delegate receives updates on homes being managed via the home manager.
 */
NS_AVAILABLE_IOS(8_0) __WATCHOS_AVAILABLE(2_0) __TVOS_AVAILABLE(10_0)
@protocol HMHomeManagerDelegate <NSObject>

@optional

/*!
 * @brief Informs the delegate when homes configured by the user have been detected by the system.
 *
 * @discussion This delegate method is also invoked to inform an application of significant changes
 *             to the home configuration. Applications should use this as a cue to invalidate their
 *             current references to HomeKit objects and refresh their views with the new list of homes.
 *
 * @param manager Sender of this message.
 */
- (void)homeManagerDidUpdateHomes:(HMHomeManager *)manager;

/*!
 * @brief Informs the delegate when the primary home is modified.
 *
 * @param manager Sender of this message.
 */
- (void)homeManagerDidUpdatePrimaryHome:(HMHomeManager *)manager;

/*!
 * @brief Informs the delegate when a new home is added.
 *
 * @param manager Sender of this message.
 *
 * @param home New home that was added.
 */
- (void)homeManager:(HMHomeManager *)manager didAddHome:(HMHome *)home;

/*!
 * @brief Informs the delegate when an existing home is removed.
 *
 * @param manager Sender of this message.
 *
 * @param home Home that was removed.
 */
- (void)homeManager:(HMHomeManager *)manager didRemoveHome:(HMHome *)home;

@end

NS_ASSUME_NONNULL_END
