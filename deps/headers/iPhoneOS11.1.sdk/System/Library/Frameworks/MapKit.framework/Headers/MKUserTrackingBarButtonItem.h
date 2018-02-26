//
//  MKUserTrackingBarButtonItem.h
//  MapKit
//
//  Copyright (c) 2010-2014, Apple Inc. All rights reserved.
//

#import <UIKit/UIBarButtonItem.h>
#import <MapKit/MKFoundation.h>

@class MKMapView;

NS_ASSUME_NONNULL_BEGIN

NS_CLASS_AVAILABLE(NA, 5_0) __TVOS_PROHIBITED __WATCHOS_PROHIBITED
@interface MKUserTrackingBarButtonItem : UIBarButtonItem

- (instancetype)initWithMapView:(nullable MKMapView *)mapView NS_DESIGNATED_INITIALIZER;
@property (nonatomic, strong, nullable) MKMapView *mapView;

@end

NS_ASSUME_NONNULL_END
