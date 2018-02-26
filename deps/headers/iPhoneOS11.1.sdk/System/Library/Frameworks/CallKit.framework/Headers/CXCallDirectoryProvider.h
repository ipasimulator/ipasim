//
//  CXCallDirectoryProvider.h
//  CallKit
//
//  Copyright © 2016 Apple. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CallKit/CXBase.h>

NS_ASSUME_NONNULL_BEGIN

@class CXCallDirectoryExtensionContext;

CX_CLASS_AVAILABLE(ios(10.0))
@interface CXCallDirectoryProvider : NSObject <NSExtensionRequestHandling>

- (void)beginRequestWithExtensionContext:(CXCallDirectoryExtensionContext *)context;

@end

NS_ASSUME_NONNULL_END
