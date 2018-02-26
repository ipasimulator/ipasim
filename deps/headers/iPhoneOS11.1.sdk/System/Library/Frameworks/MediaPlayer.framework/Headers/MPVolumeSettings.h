//
//  MPVolumeSettings.h
//  MediaPlayer
//
//  Copyright 2008 Apple, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <MediaPlayer/MediaPlayerDefines.h>

MP_EXTERN void MPVolumeSettingsAlertShow(void) MP_PROHIBITED(tvos);
MP_EXTERN void MPVolumeSettingsAlertHide(void) MP_PROHIBITED(tvos);
MP_EXTERN BOOL MPVolumeSettingsAlertIsVisible(void) MP_PROHIBITED(tvos);
