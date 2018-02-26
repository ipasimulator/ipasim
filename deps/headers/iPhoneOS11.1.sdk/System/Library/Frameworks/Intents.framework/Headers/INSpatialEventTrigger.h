//
//  INSpatialEventTrigger.h
//  Intents
//
//  Copyright (c) 2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <Intents/INSpatialEvent.h>

@class CLPlacemark;

NS_ASSUME_NONNULL_BEGIN

API_AVAILABLE(macosx(10.13), ios(11.0), watchos(4.0))
@interface INSpatialEventTrigger : NSObject

- (instancetype)initWithPlacemark:(CLPlacemark *)placemark event:(INSpatialEvent)event;

@property (readonly) CLPlacemark *placemark;
@property (readonly) INSpatialEvent event;

@end
NS_ASSUME_NONNULL_END
