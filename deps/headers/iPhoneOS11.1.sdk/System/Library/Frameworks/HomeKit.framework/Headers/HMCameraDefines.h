//
//  HMCameraDefines.h
//  HomeKit
//
//  Copyright © 2016 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

/*!
 * @abstract This enumeration describes the different states of a camera stream.
 */
__IOS_AVAILABLE(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0)
typedef NS_ENUM(NSUInteger, HMCameraStreamState)
{
    /*!
     * Start stream request is in progress.
     */
    HMCameraStreamStateStarting = 1,

    /*!
     * Streaming is in progress.
     */
    HMCameraStreamStateStreaming = 2,

    /*!
     * Stop stream request is in progress.
     */
    HMCameraStreamStateStopping = 3,

    /*!
     * No streaming is in progress.
     */
    HMCameraStreamStateNotStreaming = 4
};

/*!
 * @abstract This enumeration describes the setting for audio on the recipient of the camera stream.
 */
__IOS_AVAILABLE(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0)
typedef NS_ENUM(NSUInteger, HMCameraAudioStreamSetting)
{
    /*!
     * Muted for incoming and outgoing audio.
     */
    HMCameraAudioStreamSettingMuted = 1,

    /*!
     * Only incoming audio is allowed.
     */
    HMCameraAudioStreamSettingIncomingAudioAllowed = 2,

    /*!
     * Bidirectional audio is allowed.
     */
    HMCameraAudioStreamSettingBidirectionalAudioAllowed = 3,
};


