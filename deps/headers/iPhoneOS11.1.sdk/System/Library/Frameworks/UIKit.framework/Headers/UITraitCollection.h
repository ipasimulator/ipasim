//
//  UITraitCollection.h
//  UIKit
//
//  Copyright (c) 2013-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UIKit/UIKitDefines.h>
#import <UIKit/UIDevice.h>
#import <UIKit/UIInterface.h>
#import <UIKit/UITouch.h>
#import <UIKit/UIContentSizeCategory.h>

/*! A trait collection encapsulates the system traits of an interface's environment. */
NS_ASSUME_NONNULL_BEGIN

NS_CLASS_AVAILABLE_IOS(8_0) @interface UITraitCollection : NSObject <NSCopying, NSSecureCoding>

- (instancetype)init NS_DESIGNATED_INITIALIZER;
- (nullable instancetype)initWithCoder:(NSCoder *)aDecoder NS_DESIGNATED_INITIALIZER;

- (BOOL)containsTraitsInCollection:(nullable UITraitCollection *)trait;

/*! Returns a trait collection by merging the traits in `traitCollections`. The last trait along any given
 axis (e.g. interface usage) will supersede any others. */
+ (UITraitCollection *)traitCollectionWithTraitsFromCollections:(NSArray<UITraitCollection *> *)traitCollections;


+ (UITraitCollection *)traitCollectionWithUserInterfaceIdiom:(UIUserInterfaceIdiom)idiom;
@property (nonatomic, readonly) UIUserInterfaceIdiom userInterfaceIdiom; // unspecified: UIUserInterfaceIdiomUnspecified

+ (UITraitCollection *)traitCollectionWithUserInterfaceStyle:(UIUserInterfaceStyle)userInterfaceStyle __TVOS_AVAILABLE(10_0) __WATCHOS_PROHIBITED __IOS_PROHIBITED;
@property (nonatomic, readonly) UIUserInterfaceStyle userInterfaceStyle __TVOS_AVAILABLE(10_0) __WATCHOS_PROHIBITED __IOS_PROHIBITED; // unspecified: UIUserInterfaceStyleUnspecified

+ (UITraitCollection *)traitCollectionWithLayoutDirection:(UITraitEnvironmentLayoutDirection)layoutDirection NS_AVAILABLE_IOS(10_0);
@property (nonatomic, readonly) UITraitEnvironmentLayoutDirection layoutDirection NS_AVAILABLE_IOS(10_0); // unspecified: UITraitEnvironmentLayoutDirectionUnspecified

+ (UITraitCollection *)traitCollectionWithDisplayScale:(CGFloat)scale;
@property (nonatomic, readonly) CGFloat displayScale; // unspecified: 0.0

+ (UITraitCollection *)traitCollectionWithHorizontalSizeClass:(UIUserInterfaceSizeClass)horizontalSizeClass;
@property (nonatomic, readonly) UIUserInterfaceSizeClass horizontalSizeClass; // unspecified: UIUserInterfaceSizeClassUnspecified

+ (UITraitCollection *)traitCollectionWithVerticalSizeClass:(UIUserInterfaceSizeClass)verticalSizeClass;
@property (nonatomic, readonly) UIUserInterfaceSizeClass verticalSizeClass; // unspecified: UIUserInterfaceSizeClassUnspecified

+ (UITraitCollection *)traitCollectionWithForceTouchCapability:(UIForceTouchCapability)capability NS_AVAILABLE_IOS(9_0);
@property (nonatomic, readonly) UIForceTouchCapability forceTouchCapability NS_AVAILABLE_IOS(9_0); // unspecified: UIForceTouchCapabilityUnknown

+ (UITraitCollection *)traitCollectionWithPreferredContentSizeCategory:(UIContentSizeCategory)preferredContentSizeCategory NS_AVAILABLE_IOS(10_0);
@property (nonatomic, copy, readonly) UIContentSizeCategory preferredContentSizeCategory NS_AVAILABLE_IOS(10_0); // unspecified: UIContentSizeCategoryUnspecified

+ (UITraitCollection *)traitCollectionWithDisplayGamut:(UIDisplayGamut)displayGamut NS_AVAILABLE_IOS(10_0);
@property (nonatomic, readonly) UIDisplayGamut displayGamut NS_AVAILABLE_IOS(10_0); // unspecified: UIDisplayGamutUnspecified

@end

/*! Trait environments expose a trait collection that describes their environment. */
@protocol UITraitEnvironment <NSObject>
@property (nonatomic, readonly) UITraitCollection *traitCollection NS_AVAILABLE_IOS(8_0);

/*! To be overridden as needed to provide custom behavior when the environment's traits change. */
- (void)traitCollectionDidChange:(nullable UITraitCollection *)previousTraitCollection NS_AVAILABLE_IOS(8_0);
@end

NS_ASSUME_NONNULL_END
