//
//  HMCameraSnapshot.h
//  HomeKit
//
//  Copyright © 2016 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <HomeKit/HMCameraSource.h>

NS_ASSUME_NONNULL_BEGIN

/*!
 * @abstract Represents a camera snapshot.
 */
__IOS_AVAILABLE(10_0) __WATCHOS_AVAILABLE(3_0) __TVOS_AVAILABLE(10_0)
@interface HMCameraSnapshot : HMCameraSource

/*!
 * @brief Time corresponding to the snapshot request.
 */
@property(readonly, copy, nonatomic) NSDate *captureDate;

@end

NS_ASSUME_NONNULL_END
