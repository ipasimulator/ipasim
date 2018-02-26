//
//  INVisualCodeType.h
//  Intents
//
//  Copyright (c) 2016-2017 Apple Inc. All rights reserved.
//

#ifndef INVisualCodeType_h
#define INVisualCodeType_h

#import <Foundation/Foundation.h>
#import <Intents/IntentsDefines.h>

typedef NS_ENUM(NSInteger, INVisualCodeType) {
    INVisualCodeTypeUnknown = 0,
    INVisualCodeTypeContact,
    INVisualCodeTypeRequestPayment,
    INVisualCodeTypeSendPayment,
} API_AVAILABLE(ios(11.0), watchos(4.0)) API_UNAVAILABLE(macosx);

#endif // INVisualCodeType_h
