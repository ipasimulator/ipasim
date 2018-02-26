//
//  INUIHostedViewSiriProviding.h
//  Intents
//
//  Copyright (c) 2016 Apple Inc. All rights reserved.
//

NS_ASSUME_NONNULL_BEGIN

@protocol INUIHostedViewSiriProviding <NSObject>

@optional

@property (nonatomic, assign, readonly) BOOL displaysMap;
@property (nonatomic, assign, readonly) BOOL displaysMessage;
@property (nonatomic, assign, readonly) BOOL displaysPaymentTransaction;

@end

NS_ASSUME_NONNULL_END
