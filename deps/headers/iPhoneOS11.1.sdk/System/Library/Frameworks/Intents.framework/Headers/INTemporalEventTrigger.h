//
//  INTemporalEventTrigger.h
//  Intents
//
//  Copyright (c) 2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@class INDateComponentsRange;

NS_ASSUME_NONNULL_BEGIN

API_AVAILABLE(macosx(10.13), ios(11.0), watchos(4.0))
@interface INTemporalEventTrigger : NSObject <NSCopying, NSSecureCoding>

- (instancetype)initWithDateComponentsRange:(INDateComponentsRange *)dateComponentsRange;

@property (readonly) INDateComponentsRange *dateComponentsRange;

@end
NS_ASSUME_NONNULL_END
