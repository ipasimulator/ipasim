//
//  PKPushPayload.h
//  PushKit
//
//  Copyright (c) 2014 Apple. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <PushKit/PKDefines.h>

NS_ASSUME_NONNULL_BEGIN

NS_CLASS_AVAILABLE_IOS(8_0)
@interface PKPushPayload : NSObject

@property (readonly,copy) PKPushType type;
@property (readonly,copy) NSDictionary *dictionaryPayload;

@end

NS_ASSUME_NONNULL_END
