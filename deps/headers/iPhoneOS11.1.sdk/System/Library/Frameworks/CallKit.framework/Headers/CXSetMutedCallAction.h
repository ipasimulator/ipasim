//
//  CXSetMutedCallAction.h
//  CallKit
//
//  Copyright © 2016 Apple. All rights reserved.
//

#import <CallKit/CXCallAction.h>

NS_ASSUME_NONNULL_BEGIN

CX_CLASS_AVAILABLE(ios(10.0))
@interface CXSetMutedCallAction : CXCallAction

- (instancetype)initWithCallUUID:(NSUUID *)callUUID muted:(BOOL)muted NS_DESIGNATED_INITIALIZER;
- (nullable instancetype)initWithCoder:(NSCoder *)aDecoder NS_DESIGNATED_INITIALIZER;
- (instancetype)initWithCallUUID:(NSUUID *)callUUID NS_UNAVAILABLE;

@property (nonatomic, getter=isMuted) BOOL muted;

@end

NS_ASSUME_NONNULL_END
