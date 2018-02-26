//
//  WKInterfaceObject.h
//  WatchKit
//
//  Copyright (c) 2014-2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#if TARGET_OS_WATCH
#import <UIKit/UIAccessibilityConstants.h>
#else
#import <UIKit/UIAccessibility.h>
#endif
#import <WatchKit/WKDefines.h>
#import <WatchKit/WKInterfaceDevice.h>

NS_ASSUME_NONNULL_BEGIN

@class WKAccessibilityImageRegion;

typedef NS_ENUM(NSInteger, WKInterfaceObjectHorizontalAlignment)  {
    WKInterfaceObjectHorizontalAlignmentLeft,
    WKInterfaceObjectHorizontalAlignmentCenter,
    WKInterfaceObjectHorizontalAlignmentRight
} WK_AVAILABLE_WATCHOS_ONLY(2.0);

typedef NS_ENUM(NSInteger, WKInterfaceObjectVerticalAlignment)  {
    WKInterfaceObjectVerticalAlignmentTop,
    WKInterfaceObjectVerticalAlignmentCenter,
    WKInterfaceObjectVerticalAlignmentBottom
} WK_AVAILABLE_WATCHOS_ONLY(2.0);

WK_CLASS_AVAILABLE_IOS(8_2)
@interface WKInterfaceObject : NSObject

- (instancetype)init NS_UNAVAILABLE;

- (void)setHidden:(BOOL)hidden;
- (void)setAlpha:(CGFloat)alpha;
- (void)setSemanticContentAttribute:(WKInterfaceSemanticContentAttribute)semanticContentAttribute WK_AVAILABLE_WATCHOS_ONLY(2.1);

- (void)setHorizontalAlignment:(WKInterfaceObjectHorizontalAlignment)horizontalAlignment WK_AVAILABLE_WATCHOS_ONLY(2.0);
- (void)setVerticalAlignment:(WKInterfaceObjectVerticalAlignment)verticalAlignment WK_AVAILABLE_WATCHOS_ONLY(2.0);

- (void)setWidth:(CGFloat)width;
- (void)setHeight:(CGFloat)height;
- (void)setRelativeWidth:(CGFloat)width withAdjustment:(CGFloat)adjustment WK_AVAILABLE_WATCHOS_ONLY(2.0);
- (void)setRelativeHeight:(CGFloat)height withAdjustment:(CGFloat)adjustment WK_AVAILABLE_WATCHOS_ONLY(2.0);

- (void)sizeToFitWidth WK_AVAILABLE_WATCHOS_ONLY(2.0);
- (void)sizeToFitHeight WK_AVAILABLE_WATCHOS_ONLY(2.0);

@property (nonatomic, readonly, copy) NSString *interfaceProperty;   // same as controller's property name

@end

@interface WKInterfaceObject (WKAccessibility)

- (void)setAccessibilityIdentifier:(nullable NSString *)accessibilityIdentifier WK_AVAILABLE_WATCHOS_IOS(2.0,9.0);
- (void)setAccessibilityLabel:(nullable NSString *)accessibilityLabel;
- (void)setAccessibilityHint:(nullable NSString *)accessibilityHint;
- (void)setAccessibilityValue:(nullable NSString *)accessibilityValue;
- (void)setIsAccessibilityElement:(BOOL)isAccessibilityElement;
- (void)setAccessibilityTraits:(UIAccessibilityTraits)accessibilityTraits;
- (void)setAccessibilityImageRegions:(NSArray<WKAccessibilityImageRegion*> *)accessibilityImageRegions;          // array of WKAccessibilityImageRegion. copied

@end

WK_CLASS_AVAILABLE_IOS(8_2)
@interface WKAccessibilityImageRegion : NSObject

@property(nonatomic)      CGRect    frame;
@property(nonatomic,copy) NSString *label;

@end

NS_ASSUME_NONNULL_END
