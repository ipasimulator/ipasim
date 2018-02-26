//
//  HMAccessory+Camera.h
//  HomeKit
//
//  Copyright © 2015-2016 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <HomeKit/HMAccessory.h>

@class HMCameraProfile;

NS_ASSUME_NONNULL_BEGIN

/*!
 * @abstract Category implementing methods related to camera profile.
 */
@interface HMAccessory(Camera)

/*!
 * @brief Returns array of camera profiles implemented by the accessory.
 *
 * @discussion An accessory can contain one or more cameras. Each camera is represented as a 
 *             an HMCameraProfile object. If the accessory does not contain a camera, this property
 *             will be nil.
 */
@property(readonly, copy, nonatomic, nullable) NSArray<HMCameraProfile *> *cameraProfiles __IOS_AVAILABLE(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0);

@end

NS_ASSUME_NONNULL_END
