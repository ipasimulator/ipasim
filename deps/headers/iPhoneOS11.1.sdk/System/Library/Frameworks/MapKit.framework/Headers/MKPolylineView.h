//
//  MKPolylineView.h
//  MapKit
//
//  Copyright (c) 2010-2014, Apple Inc. All rights reserved.
//

#import <UIKit/UIKit.h>

#import <MapKit/MKPolyline.h>
#import <MapKit/MKOverlayPathView.h>
#import <MapKit/MKFoundation.h>

// Prefer MKPolylineRenderer
NS_CLASS_AVAILABLE(NA, 4_0) __TVOS_PROHIBITED __WATCHOS_PROHIBITED
@interface MKPolylineView : MKOverlayPathView

- (instancetype)initWithPolyline:(MKPolyline *)polyline NS_DEPRECATED_IOS(4_0, 7_0);

@property (nonatomic, readonly) MKPolyline *polyline NS_DEPRECATED_IOS(4_0, 7_0);

@end
