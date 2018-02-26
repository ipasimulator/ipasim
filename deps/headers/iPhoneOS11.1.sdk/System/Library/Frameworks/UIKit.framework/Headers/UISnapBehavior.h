//
//  UISnapBehavior.h
//  UIKit
//
//  Copyright (c) 2012-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIView.h>
#import <UIKit/UIDynamicBehavior.h>

NS_ASSUME_NONNULL_BEGIN

NS_CLASS_AVAILABLE_IOS(7_0) @interface UISnapBehavior : UIDynamicBehavior

// The point argument is expressed in the reference coordinate system
- (instancetype)initWithItem:(id <UIDynamicItem>)item snapToPoint:(CGPoint)point NS_DESIGNATED_INITIALIZER;

@property (nonatomic, assign) CGPoint snapPoint NS_AVAILABLE_IOS(9_0);
@property (nonatomic, assign) CGFloat damping; // damping value from 0.0 to 1.0. 1.0 is the least oscillation.

@end

NS_ASSUME_NONNULL_END
