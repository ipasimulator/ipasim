//
//  HMCameraAudioControl.h
//  HomeKit
//
//  Copyright © 2016 Apple Inc. All rights reserved.
//

#import <HomeKit/HMCameraControl.h>

@class HMCharacteristic;

NS_ASSUME_NONNULL_BEGIN

__IOS_AVAILABLE(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0)
@interface HMCameraAudioControl : HMCameraControl

- (instancetype)init NS_UNAVAILABLE;

/*!
 * Characteristic corresponding to mute setting on the camera.
 */
@property(readonly, strong, nonatomic, nullable) HMCharacteristic *mute;

/*!
 * Characteristic corresponding to volume setting on the camera.
 */
@property(readonly, strong, nonatomic, nullable) HMCharacteristic *volume;

@end

NS_ASSUME_NONNULL_END
