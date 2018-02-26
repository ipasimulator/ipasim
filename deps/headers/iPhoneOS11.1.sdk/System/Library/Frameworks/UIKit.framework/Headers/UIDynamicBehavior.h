//
//  UIDynamicBehavior.h
//  UIKit
//
//  Copyright (c) 2012-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIGeometry.h>

NS_ASSUME_NONNULL_BEGIN

@class UIDynamicAnimator;
@class UIBezierPath;

typedef NS_ENUM(NSUInteger, UIDynamicItemCollisionBoundsType) {
    UIDynamicItemCollisionBoundsTypeRectangle,
    UIDynamicItemCollisionBoundsTypeEllipse, // radii will be determined from the items bounds width, height
    UIDynamicItemCollisionBoundsTypePath
} NS_ENUM_AVAILABLE_IOS(9_0);

@protocol UIDynamicItem <NSObject>

@property (nonatomic, readwrite) CGPoint center;
@property (nonatomic, readonly) CGRect bounds;
@property (nonatomic, readwrite) CGAffineTransform transform;

@optional
/**
 The collision type represents how the dynamics system will evaluate collisions with 
 respect to the dynamic item. defaults to UIDynamicItemCollisionBoundsTypeRectangle
 */
@property (nonatomic, readonly) UIDynamicItemCollisionBoundsType collisionBoundsType NS_AVAILABLE_IOS(9_0);

/**
 The path must represent a convex polygon with counter clockwise winding and no self intersection. 
 The point (0,0) in the path corresponds to the dynamic item's center.
 */
@property (nonatomic, readonly) UIBezierPath *collisionBoundingPath NS_AVAILABLE_IOS(9_0);

@end

NS_CLASS_AVAILABLE_IOS(9_0) @interface UIDynamicItemGroup : NSObject <UIDynamicItem>

- (instancetype)initWithItems:(NSArray<id <UIDynamicItem>> *)items;

@property (nonatomic, readonly, copy) NSArray<id <UIDynamicItem>> *items;

@end

NS_CLASS_AVAILABLE_IOS(7_0) @interface UIDynamicBehavior : NSObject

- (void)addChildBehavior:(UIDynamicBehavior *)behavior;
- (void)removeChildBehavior:(UIDynamicBehavior *)behavior;

@property (nonatomic, readonly, copy) NSArray<__kindof UIDynamicBehavior *> *childBehaviors;

// When running, the dynamic animator calls the action block on every animation step.
@property (nullable, nonatomic,copy) void (^action)(void);

- (void)willMoveToAnimator:(nullable UIDynamicAnimator *)dynamicAnimator; // nil when being removed from an animator

@property (nullable, nonatomic, readonly) UIDynamicAnimator *dynamicAnimator;


@end

NS_ASSUME_NONNULL_END

