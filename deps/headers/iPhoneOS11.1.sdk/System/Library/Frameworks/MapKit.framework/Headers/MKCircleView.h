//
//  MKCircleView.h
//  MapKit
//
//  Copyright (c) 2010-2014, Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <MapKit/MKCircle.h>
#import <MapKit/MKFoundation.h>
#import <MapKit/MKOverlayPathView.h>

// Prefer MKCircleRenderer
NS_CLASS_AVAILABLE(NA, 4_0) __TVOS_PROHIBITED __WATCHOS_PROHIBITED
@interface MKCircleView : MKOverlayPathView

- (instancetype)initWithCircle:(MKCircle *)circle NS_DEPRECATED_IOS(4_0, 7_0);

@property (nonatomic, readonly) MKCircle *circle NS_DEPRECATED_IOS(4_0, 7_0);

@end
