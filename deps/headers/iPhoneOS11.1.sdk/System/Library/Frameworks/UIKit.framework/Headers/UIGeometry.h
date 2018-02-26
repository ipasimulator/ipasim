//
//  UIGeometry.h
//  UIKit
//
//  Copyright (c) 2005-2017 Apple Inc. All rights reserved.
//


#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

typedef struct UIEdgeInsets {
    CGFloat top, left, bottom, right;  // specify amount to inset (positive) for each of the edges. values can be negative to 'outset'
} UIEdgeInsets;

/* Specifically for use in methods and functions supporting user interface layout direction
 */
typedef struct NSDirectionalEdgeInsets {
    CGFloat top, leading, bottom, trailing;  // specify amount to inset (positive) for each of the edges. values can be negative to 'outset'
} NSDirectionalEdgeInsets API_AVAILABLE(ios(11.0),tvos(11.0),watchos(4.0));

typedef struct UIOffset {
    CGFloat horizontal, vertical; // specify amount to offset a position, positive for right or down, negative for left or up
} UIOffset;

typedef NS_OPTIONS(NSUInteger, UIRectEdge) {
    UIRectEdgeNone   = 0,
    UIRectEdgeTop    = 1 << 0,
    UIRectEdgeLeft   = 1 << 1,
    UIRectEdgeBottom = 1 << 2,
    UIRectEdgeRight  = 1 << 3,
    UIRectEdgeAll    = UIRectEdgeTop | UIRectEdgeLeft | UIRectEdgeBottom | UIRectEdgeRight
} NS_ENUM_AVAILABLE_IOS(7_0);

UIKIT_STATIC_INLINE UIEdgeInsets UIEdgeInsetsMake(CGFloat top, CGFloat left, CGFloat bottom, CGFloat right) {
    UIEdgeInsets insets = {top, left, bottom, right};
    return insets;
}

UIKIT_STATIC_INLINE NSDirectionalEdgeInsets NSDirectionalEdgeInsetsMake(CGFloat top, CGFloat leading, CGFloat bottom, CGFloat trailing) API_AVAILABLE(ios(11.0),tvos(11.0),watchos(4.0))
{
    NSDirectionalEdgeInsets insets = {top, leading, bottom, trailing};
    return insets;
}

UIKIT_STATIC_INLINE CGRect UIEdgeInsetsInsetRect(CGRect rect, UIEdgeInsets insets) {
    rect.origin.x    += insets.left;
    rect.origin.y    += insets.top;
    rect.size.width  -= (insets.left + insets.right);
    rect.size.height -= (insets.top  + insets.bottom);
    return rect;
}

UIKIT_STATIC_INLINE UIOffset UIOffsetMake(CGFloat horizontal, CGFloat vertical) {
    UIOffset offset = {horizontal, vertical};
    return offset;
}

UIKIT_STATIC_INLINE BOOL UIEdgeInsetsEqualToEdgeInsets(UIEdgeInsets insets1, UIEdgeInsets insets2) {
    return insets1.left == insets2.left && insets1.top == insets2.top && insets1.right == insets2.right && insets1.bottom == insets2.bottom;
}

UIKIT_STATIC_INLINE BOOL NSDirectionalEdgeInsetsEqualToDirectionalEdgeInsets(NSDirectionalEdgeInsets insets1, NSDirectionalEdgeInsets insets2) API_AVAILABLE(ios(11.0),tvos(11.0),watchos(4.0))
{
    return insets1.leading == insets2.leading && insets1.top == insets2.top && insets1.trailing == insets2.trailing && insets1.bottom == insets2.bottom;
}

UIKIT_STATIC_INLINE BOOL UIOffsetEqualToOffset(UIOffset offset1, UIOffset offset2) {
    return offset1.horizontal == offset2.horizontal && offset1.vertical == offset2.vertical;
}

#if UIKIT_REMOVE_ZERO_FROM_SWIFT
UIKIT_EXTERN const UIEdgeInsets UIEdgeInsetsZero NS_SWIFT_UNAVAILABLE("Use UIEdgeInsets.zero instead");
UIKIT_EXTERN const NSDirectionalEdgeInsets NSDirectionalEdgeInsetsZero API_AVAILABLE(ios(11.0),tvos(11.0),watchos(4.0));
UIKIT_EXTERN const UIOffset UIOffsetZero NS_SWIFT_UNAVAILABLE("Use UIOffset.zero instead");
#else
UIKIT_EXTERN const UIEdgeInsets UIEdgeInsetsZero;
UIKIT_EXTERN const NSDirectionalEdgeInsets NSDirectionalEdgeInsetsZero;
UIKIT_EXTERN const UIOffset UIOffsetZero;
#endif

UIKIT_EXTERN NSString *NSStringFromCGPoint(CGPoint point);
UIKIT_EXTERN NSString *NSStringFromCGVector(CGVector vector);
UIKIT_EXTERN NSString *NSStringFromCGSize(CGSize size);
UIKIT_EXTERN NSString *NSStringFromCGRect(CGRect rect);
UIKIT_EXTERN NSString *NSStringFromCGAffineTransform(CGAffineTransform transform);
UIKIT_EXTERN NSString *NSStringFromUIEdgeInsets(UIEdgeInsets insets);
UIKIT_EXTERN NSString *NSStringFromDirectionalEdgeInsets(NSDirectionalEdgeInsets insets) API_AVAILABLE(ios(11.0),tvos(11.0),watchos(4.0));
UIKIT_EXTERN NSString *NSStringFromUIOffset(UIOffset offset);

UIKIT_EXTERN CGPoint CGPointFromString(NSString *string);
UIKIT_EXTERN CGVector CGVectorFromString(NSString *string);
UIKIT_EXTERN CGSize CGSizeFromString(NSString *string);
UIKIT_EXTERN CGRect CGRectFromString(NSString *string);
UIKIT_EXTERN CGAffineTransform CGAffineTransformFromString(NSString *string);
UIKIT_EXTERN UIEdgeInsets UIEdgeInsetsFromString(NSString *string);
UIKIT_EXTERN NSDirectionalEdgeInsets NSDirectionalEdgeInsetsFromString(NSString *string) API_AVAILABLE(ios(11.0),tvos(11.0),watchos(4.0));
UIKIT_EXTERN UIOffset UIOffsetFromString(NSString *string);

@interface NSValue (NSValueUIGeometryExtensions)

+ (NSValue *)valueWithCGPoint:(CGPoint)point;
+ (NSValue *)valueWithCGVector:(CGVector)vector;
+ (NSValue *)valueWithCGSize:(CGSize)size;
+ (NSValue *)valueWithCGRect:(CGRect)rect;
+ (NSValue *)valueWithCGAffineTransform:(CGAffineTransform)transform;
+ (NSValue *)valueWithUIEdgeInsets:(UIEdgeInsets)insets;
+ (NSValue *)valueWithDirectionalEdgeInsets:(NSDirectionalEdgeInsets)insets API_AVAILABLE(ios(11.0),tvos(11.0),watchos(4.0));
+ (NSValue *)valueWithUIOffset:(UIOffset)insets NS_AVAILABLE_IOS(5_0);

#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly) CGPoint CGPointValue;
@property(nonatomic, readonly) CGVector CGVectorValue;
@property(nonatomic, readonly) CGSize CGSizeValue;
@property(nonatomic, readonly) CGRect CGRectValue;
@property(nonatomic, readonly) CGAffineTransform CGAffineTransformValue;
@property(nonatomic, readonly) UIEdgeInsets UIEdgeInsetsValue;
@property(nonatomic, readonly) NSDirectionalEdgeInsets directionalEdgeInsetsValue API_AVAILABLE(ios(11.0),tvos(11.0),watchos(4.0));
@property(nonatomic, readonly) UIOffset UIOffsetValue NS_AVAILABLE_IOS(5_0);
#else
- (CGPoint)CGPointValue;
- (CGVector)CGVectorValue;
- (CGSize)CGSizeValue;
- (CGRect)CGRectValue;
- (CGAffineTransform)CGAffineTransformValue;
- (UIEdgeInsets)UIEdgeInsetsValue;
- (NSDirectionalEdgeInsets)directionalEdgeInsetsValue API_AVAILABLE(ios(11.0),tvos(11.0),watchos(4.0));
- (UIOffset)UIOffsetValue NS_AVAILABLE_IOS(5_0);
#endif

@end
    
@interface NSCoder (UIGeometryKeyedCoding)

- (void)encodeCGPoint:(CGPoint)point forKey:(NSString *)key;
- (void)encodeCGVector:(CGVector)vector forKey:(NSString *)key;
- (void)encodeCGSize:(CGSize)size forKey:(NSString *)key;
- (void)encodeCGRect:(CGRect)rect forKey:(NSString *)key;
- (void)encodeCGAffineTransform:(CGAffineTransform)transform forKey:(NSString *)key;
- (void)encodeUIEdgeInsets:(UIEdgeInsets)insets forKey:(NSString *)key;
- (void)encodeDirectionalEdgeInsets:(NSDirectionalEdgeInsets)insets forKey:(NSString *)key API_AVAILABLE(ios(11.0),tvos(11.0),watchos(4.0));
- (void)encodeUIOffset:(UIOffset)offset forKey:(NSString *)key NS_AVAILABLE_IOS(5_0);

- (CGPoint)decodeCGPointForKey:(NSString *)key;
- (CGVector)decodeCGVectorForKey:(NSString *)key;
- (CGSize)decodeCGSizeForKey:(NSString *)key;
- (CGRect)decodeCGRectForKey:(NSString *)key;
- (CGAffineTransform)decodeCGAffineTransformForKey:(NSString *)key;
- (UIEdgeInsets)decodeUIEdgeInsetsForKey:(NSString *)key;
- (NSDirectionalEdgeInsets)decodeDirectionalEdgeInsetsForKey:(NSString *)key API_AVAILABLE(ios(11.0),tvos(11.0),watchos(4.0));
- (UIOffset)decodeUIOffsetForKey:(NSString *)key NS_AVAILABLE_IOS(5_0);

@end

NS_ASSUME_NONNULL_END
