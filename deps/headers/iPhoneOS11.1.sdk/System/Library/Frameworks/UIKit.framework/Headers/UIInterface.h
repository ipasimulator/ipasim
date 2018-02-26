//
//  UIInterface.h
//  UIKit
//
//  Copyright (c) 2005-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>
#import <UIKit/UIColor.h>
#import <UIKit/UIFont.h>

// for UINavigationBar and UIToolBar

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, UIBarStyle) {
    UIBarStyleDefault          = 0,
    UIBarStyleBlack            = 1,
    
    UIBarStyleBlackOpaque      = 1, // Deprecated. Use UIBarStyleBlack
    UIBarStyleBlackTranslucent = 2, // Deprecated. Use UIBarStyleBlack and set the translucent property to YES
} __TVOS_PROHIBITED;

typedef NS_ENUM(NSInteger, UIUserInterfaceSizeClass) {
    UIUserInterfaceSizeClassUnspecified = 0,
    UIUserInterfaceSizeClassCompact     = 1,
    UIUserInterfaceSizeClassRegular     = 2,
} NS_ENUM_AVAILABLE_IOS(8_0);

typedef NS_ENUM(NSInteger, UIUserInterfaceStyle) {
    UIUserInterfaceStyleUnspecified,
    UIUserInterfaceStyleLight,
    UIUserInterfaceStyleDark,
} __TVOS_AVAILABLE(10_0) __IOS_PROHIBITED __WATCHOS_PROHIBITED;

typedef NS_ENUM(NSInteger, UIUserInterfaceLayoutDirection) {
    UIUserInterfaceLayoutDirectionLeftToRight,
    UIUserInterfaceLayoutDirectionRightToLeft,
} NS_ENUM_AVAILABLE_IOS(5_0);

// These values are only used for the layout direction trait, which informs but does not completely dictate the layout direction of views. To determine the effective layout direction of a view, consult the UIView.effectiveUserInterfaceLayoutDirection property, whose values are members of the UIUserInterfaceLayoutDirection enum.
typedef NS_ENUM(NSInteger, UITraitEnvironmentLayoutDirection) {
    UITraitEnvironmentLayoutDirectionUnspecified = -1,
    UITraitEnvironmentLayoutDirectionLeftToRight = UIUserInterfaceLayoutDirectionLeftToRight,
    UITraitEnvironmentLayoutDirectionRightToLeft = UIUserInterfaceLayoutDirectionRightToLeft,
} NS_ENUM_AVAILABLE_IOS(10_0);

typedef NS_ENUM(NSInteger, UIDisplayGamut) {
    UIDisplayGamutUnspecified = -1,
    UIDisplayGamutSRGB,
    UIDisplayGamutP3
} NS_ENUM_AVAILABLE_IOS(10_0);


// System colors

@interface UIColor (UIColorSystemColors)
#if UIKIT_DEFINE_AS_PROPERTIES
@property(class, nonatomic, readonly) UIColor *lightTextColor __TVOS_PROHIBITED;                // for a dark background
@property(class, nonatomic, readonly) UIColor *darkTextColor __TVOS_PROHIBITED;                 // for a light background

@property(class, nonatomic, readonly) UIColor *groupTableViewBackgroundColor __TVOS_PROHIBITED;

@property(class, nonatomic, readonly) UIColor *viewFlipsideBackgroundColor NS_DEPRECATED_IOS(2_0, 7_0) __TVOS_PROHIBITED;
@property(class, nonatomic, readonly) UIColor *scrollViewTexturedBackgroundColor NS_DEPRECATED_IOS(3_2, 7_0) __TVOS_PROHIBITED;
@property(class, nonatomic, readonly) UIColor *underPageBackgroundColor NS_DEPRECATED_IOS(5_0, 7_0) __TVOS_PROHIBITED;
#else
+ (UIColor *)lightTextColor __TVOS_PROHIBITED;                // for a dark background
+ (UIColor *)darkTextColor __TVOS_PROHIBITED;                 // for a light background

+ (UIColor *)groupTableViewBackgroundColor __TVOS_PROHIBITED;

+ (UIColor *)viewFlipsideBackgroundColor NS_DEPRECATED_IOS(2_0, 7_0) __TVOS_PROHIBITED;
+ (UIColor *)scrollViewTexturedBackgroundColor NS_DEPRECATED_IOS(3_2, 7_0) __TVOS_PROHIBITED;
+ (UIColor *)underPageBackgroundColor NS_DEPRECATED_IOS(5_0, 7_0) __TVOS_PROHIBITED;
#endif
@end

// System fonts

@interface UIFont (UIFontSystemFonts)
#if UIKIT_DEFINE_AS_PROPERTIES
@property(class, nonatomic, readonly) CGFloat labelFontSize __TVOS_PROHIBITED;
@property(class, nonatomic, readonly) CGFloat buttonFontSize __TVOS_PROHIBITED;
@property(class, nonatomic, readonly) CGFloat smallSystemFontSize __TVOS_PROHIBITED;
@property(class, nonatomic, readonly) CGFloat systemFontSize __TVOS_PROHIBITED;
#else
+ (CGFloat)labelFontSize __TVOS_PROHIBITED;
+ (CGFloat)buttonFontSize __TVOS_PROHIBITED;
+ (CGFloat)smallSystemFontSize __TVOS_PROHIBITED;
+ (CGFloat)systemFontSize __TVOS_PROHIBITED;
#endif
@end

NS_ASSUME_NONNULL_END
