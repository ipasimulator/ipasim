// =================================================================================================
// CAInterAppAudioTransportView.h
// =================================================================================================
/*
 File:		CAInterAppAudioTransportView.h
 Framework:	CoreAudioKit
 
 Copyright (c) 2014 Apple Inc. All Rights Reserved.
 */

#import <UIKit/UIKit.h>
#import <AudioUnit/AudioUnit.h>

NS_CLASS_AVAILABLE_IOS(8_0)

NS_ASSUME_NONNULL_BEGIN
@interface CAInterAppAudioTransportView : UIView
@property(getter=isEnabled)							BOOL enabled;

@property(nonatomic,readonly,getter=isPlaying)		BOOL playing;
@property(nonatomic,readonly,getter=isRecording)	BOOL recording;
@property(nonatomic,readonly,getter=isConnected)	BOOL connected;

/* Appearance properties */
@property(nonatomic,strong)UIColor *labelColor;
@property(nonatomic,strong)UIFont  *currentTimeLabelFont;

@property(nonatomic,strong)UIColor *rewindButtonColor;
@property(nonatomic,strong)UIColor *playButtonColor;
@property(nonatomic,strong)UIColor *pauseButtonColor;
@property(nonatomic,strong)UIColor *recordButtonColor;

-(void) setOutputAudioUnit: (AudioUnit) au;

@end
NS_ASSUME_NONNULL_END
