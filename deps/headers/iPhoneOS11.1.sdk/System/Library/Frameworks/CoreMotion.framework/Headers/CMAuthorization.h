/*
 *  CMAuthorization.h
 *  CoreMotion
 *
 *  Copyright (c) 2017 Apple Inc. All rights reserved.
 *
 */

#import <Foundation/Foundation.h>

/*
 *  CMAuthorizationStatus
 *
 *  Discussion:
 *      Represents the current motion authorization state.
 *
 *      CMAuthorizationStatusNotDetermined when the user has not been prompted yet.
 *      CMAuthorizationStatusRestricted when access is denied due to system-wide restrictions.
 *      CMAuthorizationStatusDenied when access is denied by the user.
 *      CMAuthorizationStatusAuthorized when access is authorized by the user.
 *
 */
typedef NS_ENUM(NSInteger, CMAuthorizationStatus) {
	CMAuthorizationStatusNotDetermined = 0,
	CMAuthorizationStatusRestricted,
	CMAuthorizationStatusDenied,
	CMAuthorizationStatusAuthorized
} NS_ENUM_AVAILABLE(NA, 11_0) __WATCHOS_AVAILABLE(4.0) __TVOS_PROHIBITED;
