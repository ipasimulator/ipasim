//
//  CXCall.h
//  CallKit
//
//  Copyright © 2016 Apple. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CallKit/CXBase.h>

NS_ASSUME_NONNULL_BEGIN

CX_CLASS_AVAILABLE(ios(10.0))
@interface CXCall : NSObject

@property (nonatomic, readonly, copy) NSUUID *UUID;

@property (nonatomic, readonly, assign, getter=isOutgoing) BOOL outgoing;
@property (nonatomic, readonly, assign, getter=isOnHold) BOOL onHold;
@property (nonatomic, readonly, assign) BOOL hasConnected;
@property (nonatomic, readonly, assign) BOOL hasEnded;

- (instancetype)init NS_UNAVAILABLE;

- (BOOL)isEqualToCall:(CXCall *)call NS_SWIFT_UNAVAILABLE("Use == operator instead");

@end

NS_ASSUME_NONNULL_END
