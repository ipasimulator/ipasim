//
//  HMCameraProfile.h
//  HomeKit
//
//  Copyright © 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <HomeKit/HMAccessoryProfile.h>

NS_ASSUME_NONNULL_BEGIN

@class HMCameraStreamControl;
@class HMCameraSnapshotControl;
@class HMCameraSettingsControl;
@class HMCameraAudioControl;


/*!
 * @abstract Represents a camera profile the accessory implements.
 *
 * @discussion Provides an interface to interact with a Camera in an Accessory.
 */
__IOS_AVAILABLE(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0)
@interface HMCameraProfile : HMAccessoryProfile

- (instancetype)init NS_UNAVAILABLE;

/*!
 * @brief Object that can be used to control the camera stream.
 */
@property(readonly, strong, nonatomic, nullable) HMCameraStreamControl *streamControl;

/*!
 * @brief Object that can be used to take image snapshots from the camera.
 */
@property(readonly, strong, nonatomic, nullable) HMCameraSnapshotControl *snapshotControl;

/*!
 * @brief Object that can be used to control the settings on the camera.
 */
@property(readonly, strong, nonatomic, nullable) HMCameraSettingsControl *settingsControl;

/*!
 * @brief Object that can be used to control the speaker settings on the camera.
 */
@property(readonly, strong, nonatomic, nullable) HMCameraAudioControl *speakerControl;

/*!
 * @brief Object that can be used to control the microphone settings on the camera.
 */
@property(readonly, strong, nonatomic, nullable) HMCameraAudioControl *microphoneControl;

@end


NS_ASSUME_NONNULL_END

