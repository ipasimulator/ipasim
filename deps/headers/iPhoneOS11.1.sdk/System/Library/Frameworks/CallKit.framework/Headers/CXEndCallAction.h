//
//  CXEndCallAction.h
//  CallKit
//
//  Copyright © 2015 Apple. All rights reserved.
//

#import <CallKit/CXCallAction.h>

NS_ASSUME_NONNULL_BEGIN

CX_CLASS_AVAILABLE(ios(10.0))
@interface CXEndCallAction : CXCallAction

/// Normally, providers can just call -[CXAction fulfill] to indicate action fulfillment. Use this method to note a specific date that the call ended.
- (void)fulfillWithDateEnded:(NSDate *)dateEnded;

@end

NS_ASSUME_NONNULL_END
