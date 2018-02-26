//
//  HMCameraSettingsControl.h
//  HomeKit
//
//  Copyright © 2016 Apple Inc. All rights reserved.
//

#import <HomeKit/HMCameraControl.h>

@class HMCharacteristic;

NS_ASSUME_NONNULL_BEGIN

/*!
 * @abstract This class can be used to control the settings on a camera.
 */
__IOS_AVAILABLE(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0)
@interface HMCameraSettingsControl : HMCameraControl

- (instancetype)init NS_UNAVAILABLE;

/*!
 *  Characteristic corresponding to night vision setting on the camera.
 */
@property(readonly, strong, nonatomic, nullable) HMCharacteristic *nightVision;

/*!
 * Characteristic corresponding to current horizontal tilt setting on the camera.
 */
@property(readonly, strong, nonatomic, nullable) HMCharacteristic *currentHorizontalTilt;

/*!
 * Characteristic corresponding to target horizontal tilt setting on the camera.
 */
@property(readonly, strong, nonatomic, nullable) HMCharacteristic *targetHorizontalTilt;

/*!
 * Characteristic corresponding to current vertical tilt setting on the camera.
 */
@property(readonly, strong, nonatomic, nullable) HMCharacteristic *currentVerticalTilt;

/*!
 * Characteristic corresponding to target vertical tilt setting on the camera.
 */
@property(readonly, strong, nonatomic, nullable) HMCharacteristic *targetVerticalTilt;

/*!
 * Characteristic corresponding to optical zoom setting on the camera.
 */
@property(readonly, strong, nonatomic, nullable) HMCharacteristic *opticalZoom;

/*!
 * Characteristic corresponding to digital zoom setting on the camera.
 */
@property(readonly, strong, nonatomic, nullable) HMCharacteristic *digitalZoom;

/*!
 * Characteristic corresponding to image rotation setting on the camera.
 */
@property(readonly, strong, nonatomic, nullable) HMCharacteristic *imageRotation;

/*!
 * Characteristic corresponding to image mirroring setting on the camera.
 */
@property(readonly, strong, nonatomic, nullable) HMCharacteristic *imageMirroring;

@end

NS_ASSUME_NONNULL_END
