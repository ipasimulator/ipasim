//
//  WKInterfaceHMCamera.h
//  WatchKit
//
//  Copyright © 2016 Apple Inc. All rights reserved.
//

#import <WatchKit/WatchKit.h>
#import <HomeKit/HomeKit.h>

@class HMCameraSource;

WK_AVAILABLE_WATCHOS_ONLY(3.0)
@interface WKInterfaceHMCamera : WKInterfaceObject

// Pass nil to clear out the camera source.
- (void)setCameraSource:(nullable HMCameraSource *)cameraSource;

@end
