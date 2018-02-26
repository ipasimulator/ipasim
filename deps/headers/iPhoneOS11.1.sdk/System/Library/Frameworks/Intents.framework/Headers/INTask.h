//
//  INTask.h
//  Intents
//
//  Copyright (c) 2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <Intents/INTaskStatus.h>
#import <Intents/INTaskType.h>

@class INSpatialEventTrigger;
@class INSpeakableString;
@class INTemporalEventTrigger;
@class NSDateComponents;

NS_ASSUME_NONNULL_BEGIN
API_AVAILABLE(macosx(10.13), ios(11.0), watchos(4.0))
@interface INTask : NSObject <NSCopying, NSSecureCoding>

- (instancetype)initWithTitle:(INSpeakableString *)title status:(INTaskStatus)status taskType:(INTaskType)taskType spatialEventTrigger:(nullable INSpatialEventTrigger *)spatialEventTrigger temporalEventTrigger:(nullable INTemporalEventTrigger *)temporalEventTrigger createdDateComponents:(nullable NSDateComponents *)createdDateComponents modifiedDateComponents:(nullable NSDateComponents *)modifiedDateComponents identifier:(nullable NSString *)identifier;

@property (readonly, copy) INSpeakableString *title;
@property (readonly) INTaskStatus status;
@property (readonly) INTaskType taskType;
@property (readonly, copy, nullable) INSpatialEventTrigger *spatialEventTrigger;
@property (readonly, copy, nullable) INTemporalEventTrigger *temporalEventTrigger;
@property (readonly, copy, nullable) NSDateComponents *createdDateComponents;
@property (readonly, copy, nullable) NSDateComponents *modifiedDateComponents;
@property (readonly, copy, nullable) NSString *identifier;

@end
NS_ASSUME_NONNULL_END
