//
//  WKError.h
//  WatchKit
//
//  Copyright (c) 2014-2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>

NS_ASSUME_NONNULL_BEGIN

WKI_EXTERN NSString * const WatchKitErrorDomain NS_AVAILABLE_IOS(8_2);

typedef NS_ENUM(NSInteger, WatchKitErrorCode)  {
    WatchKitUnknownError                                          = 1,  // unknown error
    WatchKitApplicationDelegateWatchKitRequestReplyNotCalledError = 2,  // in iOS app's -[UIApplicationDelegate application:handleWatchKitExtensionRequest:reply:], reply was never called
    WatchKitInvalidArgumentError                                  = 3,  // invalid argument error
    WatchKitMediaPlayerError                                      = 4,  // media player error
    WatchKitDownloadError                                         = 5,  // download of resource failed
    WatchKitRecordingFailedError                                  = 6,  // recording failed
} NS_ENUM_AVAILABLE_IOS(8_2);

NS_ASSUME_NONNULL_END
