/*
 File: ASIdentifierManager.h
 
 Framework: AdSupport
 
 Copyright (c) 2012, Apple Inc. All rights reserved.
*/

#import <Foundation/Foundation.h>

NS_CLASS_AVAILABLE(NA, 6_0)
@interface ASIdentifierManager : NSObject

+ (ASIdentifierManager * _Nonnull)sharedManager;

@property (nonnull, nonatomic, readonly) NSUUID *advertisingIdentifier;
@property (nonatomic, readonly, getter=isAdvertisingTrackingEnabled) BOOL advertisingTrackingEnabled;

@end
