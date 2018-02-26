//
//  UIGravityBehavior.h
//  UIKit
//
//  Copyright (c) 2012-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIView.h>
#import <UIKit/UIDynamicBehavior.h>

NS_ASSUME_NONNULL_BEGIN

NS_CLASS_AVAILABLE_IOS(7_0) @interface UIGravityBehavior : UIDynamicBehavior

- (instancetype)initWithItems:(NSArray<id <UIDynamicItem>> *)items NS_DESIGNATED_INITIALIZER;

- (void)addItem:(id <UIDynamicItem>)item;
- (void)removeItem:(id <UIDynamicItem>)item;
@property (nonatomic, readonly, copy) NSArray<id <UIDynamicItem>> *items;

// The default value for the gravity vector is (0.0, 1.0)
// The acceleration for a dynamic item subject to a (0.0, 1.0) gravity vector is downwards at 1000 points per second².
@property (readwrite, nonatomic) CGVector gravityDirection;

@property (readwrite, nonatomic) CGFloat angle;
@property (readwrite, nonatomic) CGFloat magnitude;
- (void)setAngle:(CGFloat)angle magnitude:(CGFloat)magnitude;

@end

NS_ASSUME_NONNULL_END
