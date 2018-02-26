//
//  UIBezierPath.h
//  UIKit
//
//  Copyright (c) 2009-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_OPTIONS(NSUInteger, UIRectCorner) {
    UIRectCornerTopLeft     = 1 << 0,
    UIRectCornerTopRight    = 1 << 1,
    UIRectCornerBottomLeft  = 1 << 2,
    UIRectCornerBottomRight = 1 << 3,
    UIRectCornerAllCorners  = ~0UL
};

NS_CLASS_AVAILABLE_IOS(3_2) @interface UIBezierPath : NSObject<NSCopying, NSSecureCoding>

+ (instancetype)bezierPath;
+ (instancetype)bezierPathWithRect:(CGRect)rect;
+ (instancetype)bezierPathWithOvalInRect:(CGRect)rect;
+ (instancetype)bezierPathWithRoundedRect:(CGRect)rect cornerRadius:(CGFloat)cornerRadius; // rounds all corners with the same horizontal and vertical radius
+ (instancetype)bezierPathWithRoundedRect:(CGRect)rect byRoundingCorners:(UIRectCorner)corners cornerRadii:(CGSize)cornerRadii;
+ (instancetype)bezierPathWithArcCenter:(CGPoint)center radius:(CGFloat)radius startAngle:(CGFloat)startAngle endAngle:(CGFloat)endAngle clockwise:(BOOL)clockwise;
+ (instancetype)bezierPathWithCGPath:(CGPathRef)CGPath;

- (instancetype)init NS_DESIGNATED_INITIALIZER;
- (nullable instancetype)initWithCoder:(NSCoder *)aDecoder NS_DESIGNATED_INITIALIZER;

// Returns an immutable CGPathRef which is only valid until the UIBezierPath is further mutated.
// Setting the path will create an immutable copy of the provided CGPathRef, so any further mutations on a provided CGMutablePathRef will be ignored.
@property(nonatomic) CGPathRef CGPath;
- (CGPathRef)CGPath NS_RETURNS_INNER_POINTER CF_RETURNS_NOT_RETAINED;

// Path construction

- (void)moveToPoint:(CGPoint)point;
- (void)addLineToPoint:(CGPoint)point;
- (void)addCurveToPoint:(CGPoint)endPoint controlPoint1:(CGPoint)controlPoint1 controlPoint2:(CGPoint)controlPoint2;
- (void)addQuadCurveToPoint:(CGPoint)endPoint controlPoint:(CGPoint)controlPoint;
- (void)addArcWithCenter:(CGPoint)center radius:(CGFloat)radius startAngle:(CGFloat)startAngle endAngle:(CGFloat)endAngle clockwise:(BOOL)clockwise NS_AVAILABLE_IOS(4_0);
- (void)closePath;

- (void)removeAllPoints;

// Appending paths

- (void)appendPath:(UIBezierPath *)bezierPath;

// Modified paths

- (UIBezierPath *)bezierPathByReversingPath NS_AVAILABLE_IOS(6_0);

// Transforming paths

- (void)applyTransform:(CGAffineTransform)transform;

// Path info

@property(readonly,getter=isEmpty) BOOL empty;
@property(nonatomic,readonly) CGRect bounds;
@property(nonatomic,readonly) CGPoint currentPoint;
- (BOOL)containsPoint:(CGPoint)point;

// Drawing properties

@property(nonatomic) CGFloat lineWidth;
@property(nonatomic) CGLineCap lineCapStyle;
@property(nonatomic) CGLineJoin lineJoinStyle;
@property(nonatomic) CGFloat miterLimit; // Used when lineJoinStyle is kCGLineJoinMiter
@property(nonatomic) CGFloat flatness;
@property(nonatomic) BOOL usesEvenOddFillRule; // Default is NO. When YES, the even-odd fill rule is used for drawing, clipping, and hit testing.

- (void)setLineDash:(nullable const CGFloat *)pattern count:(NSInteger)count phase:(CGFloat)phase;
- (void)getLineDash:(nullable CGFloat *)pattern count:(nullable NSInteger *)count phase:(nullable CGFloat *)phase;

// Path operations on the current graphics context

- (void)fill;
- (void)stroke;

// These methods do not affect the blend mode or alpha of the current graphics context
- (void)fillWithBlendMode:(CGBlendMode)blendMode alpha:(CGFloat)alpha;
- (void)strokeWithBlendMode:(CGBlendMode)blendMode alpha:(CGFloat)alpha;

- (void)addClip;

@end

NS_ASSUME_NONNULL_END
