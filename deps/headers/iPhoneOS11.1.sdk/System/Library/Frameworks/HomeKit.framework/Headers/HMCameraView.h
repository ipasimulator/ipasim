//
//  HMCameraView.h
//  HomeKit
//
//  Copyright © 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <UIKit/UIKit.h>

@class HMCameraSource;

NS_ASSUME_NONNULL_BEGIN

/*!
 * @abstract This view can render a camera source.
 */
__IOS_AVAILABLE(10_0) __WATCHOS_PROHIBITED __TVOS_AVAILABLE(10_0)
@interface HMCameraView : UIView

/*!
 * @brief Represents the camera source.
 */
@property (strong, nonatomic, nullable) HMCameraSource *cameraSource;

@end

NS_ASSUME_NONNULL_END
