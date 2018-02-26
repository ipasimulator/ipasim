//
//  UIDataDetectors.h
//  UIKit
//
//  Copyright (c) 2009-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_OPTIONS(NSUInteger, UIDataDetectorTypes) {
    UIDataDetectorTypePhoneNumber                                        = 1 << 0, // Phone number detection
    UIDataDetectorTypeLink                                               = 1 << 1, // URL detection
    UIDataDetectorTypeAddress NS_ENUM_AVAILABLE_IOS(4_0)                 = 1 << 2, // Street address detection
    UIDataDetectorTypeCalendarEvent NS_ENUM_AVAILABLE_IOS(4_0)           = 1 << 3, // Event detection
    UIDataDetectorTypeShipmentTrackingNumber NS_ENUM_AVAILABLE_IOS(10_0) = 1 << 4, // Shipment tracking number detection
    UIDataDetectorTypeFlightNumber NS_ENUM_AVAILABLE_IOS(10_0)           = 1 << 5, // Flight number detection
    UIDataDetectorTypeLookupSuggestion NS_ENUM_AVAILABLE_IOS(10_0)       = 1 << 6, // Information users may want to look up

    UIDataDetectorTypeNone          = 0,               // Disable detection
    UIDataDetectorTypeAll           = NSUIntegerMax    // Enable all types, including types that may be added later
} __TVOS_PROHIBITED;
