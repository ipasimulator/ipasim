//
//  INTaskList.h
//  Intents
//
//  Copyright (c) 2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@class INSpeakableString;
@class INTask;
@class NSDateComponents;

NS_ASSUME_NONNULL_BEGIN
API_AVAILABLE(macosx(10.13), ios(11.0), watchos(4.0))
@interface INTaskList : NSObject <NSCopying, NSSecureCoding>

- (instancetype)initWithTitle:(INSpeakableString *)title tasks:(NSArray <INTask *> *)tasks groupName:(nullable INSpeakableString *)groupName createdDateComponents:(nullable NSDateComponents *)createdDateComponents modifiedDateComponents:(nullable NSDateComponents *)modifiedDateComponents identifier:(nullable NSString *)identifier;

@property (readonly, copy) INSpeakableString *title;
@property (readonly, copy) NSArray <INTask *> *tasks;
@property (readonly, copy, nullable) INSpeakableString *groupName;
@property (readonly, copy, nullable) NSDateComponents *createdDateComponents;
@property (readonly, copy, nullable) NSDateComponents *modifiedDateComponents;
@property (readonly, copy, nullable) NSString *identifier;

@end
NS_ASSUME_NONNULL_END

