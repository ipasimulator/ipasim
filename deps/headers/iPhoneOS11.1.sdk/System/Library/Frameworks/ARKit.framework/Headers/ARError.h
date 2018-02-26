//
//  ARError.h
//  ARKit
//
//  Copyright © 2016-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos)
FOUNDATION_EXTERN NSString *const ARErrorDomain;

API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos)
typedef NS_ERROR_ENUM(ARErrorDomain, ARErrorCode) {
    /** Unsupported configuration. */
    ARErrorCodeUnsupportedConfiguration   = 100,
    
    /** A sensor required to run the session is not available. */
    ARErrorCodeSensorUnavailable          = 101,
    
    /** A sensor failed to provide the required input. */
    ARErrorCodeSensorFailed               = 102,
    
    /** App does not have permission to use the camera. The user may change this in settings. */
    ARErrorCodeCameraUnauthorized         = 103,
    
    /** World tracking has encountered a fatal error. */
    ARErrorCodeWorldTrackingFailed        = 200,
};

NS_ASSUME_NONNULL_END
