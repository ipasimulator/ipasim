//
//  UIColor.h
//  UIKit
//
//  Copyright (c) 2005-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#if __has_include(<CoreImage/CoreImage.h>)
#import <CoreImage/CoreImage.h>
#endif
#import <UIKit/UIKitDefines.h>


NS_ASSUME_NONNULL_BEGIN

@class UIImage;
@class UITraitCollection;

NS_CLASS_AVAILABLE_IOS(2_0) @interface UIColor : NSObject <NSSecureCoding, NSCopying>

// Convenience methods for creating colors
+ (UIColor *)colorWithWhite:(CGFloat)white alpha:(CGFloat)alpha;
+ (UIColor *)colorWithHue:(CGFloat)hue saturation:(CGFloat)saturation brightness:(CGFloat)brightness alpha:(CGFloat)alpha;
+ (UIColor *)colorWithRed:(CGFloat)red green:(CGFloat)green blue:(CGFloat)blue alpha:(CGFloat)alpha;
+ (UIColor *)colorWithDisplayP3Red:(CGFloat)displayP3Red green:(CGFloat)green blue:(CGFloat)blue alpha:(CGFloat)alpha NS_AVAILABLE_IOS(10_0);
+ (UIColor *)colorWithCGColor:(CGColorRef)cgColor;
+ (UIColor *)colorWithPatternImage:(UIImage *)image;
#if __has_include(<CoreImage/CoreImage.h>)
+ (UIColor *)colorWithCIColor:(CIColor *)ciColor NS_AVAILABLE_IOS(5_0);
#endif

// Initializers for creating colors
- (UIColor *)initWithWhite:(CGFloat)white alpha:(CGFloat)alpha;
- (UIColor *)initWithHue:(CGFloat)hue saturation:(CGFloat)saturation brightness:(CGFloat)brightness alpha:(CGFloat)alpha;
- (UIColor *)initWithRed:(CGFloat)red green:(CGFloat)green blue:(CGFloat)blue alpha:(CGFloat)alpha;
- (UIColor *)initWithDisplayP3Red:(CGFloat)displayP3Red green:(CGFloat)green blue:(CGFloat)blue alpha:(CGFloat)alpha NS_AVAILABLE_IOS(10_0);
- (UIColor *)initWithCGColor:(CGColorRef)cgColor;
- (UIColor *)initWithPatternImage:(UIImage*)image;
#if __has_include(<CoreImage/CoreImage.h>)
- (UIColor *)initWithCIColor:(CIColor *)ciColor NS_AVAILABLE_IOS(5_0);
#endif

// Some convenience methods to create colors.  These colors will be as calibrated as possible.
// These colors are cached.
#if UIKIT_DEFINE_AS_PROPERTIES
@property(class, nonatomic, readonly) UIColor *blackColor;      // 0.0 white
@property(class, nonatomic, readonly) UIColor *darkGrayColor;   // 0.333 white
@property(class, nonatomic, readonly) UIColor *lightGrayColor;  // 0.667 white
@property(class, nonatomic, readonly) UIColor *whiteColor;      // 1.0 white
@property(class, nonatomic, readonly) UIColor *grayColor;       // 0.5 white
@property(class, nonatomic, readonly) UIColor *redColor;        // 1.0, 0.0, 0.0 RGB
@property(class, nonatomic, readonly) UIColor *greenColor;      // 0.0, 1.0, 0.0 RGB
@property(class, nonatomic, readonly) UIColor *blueColor;       // 0.0, 0.0, 1.0 RGB
@property(class, nonatomic, readonly) UIColor *cyanColor;       // 0.0, 1.0, 1.0 RGB
@property(class, nonatomic, readonly) UIColor *yellowColor;     // 1.0, 1.0, 0.0 RGB
@property(class, nonatomic, readonly) UIColor *magentaColor;    // 1.0, 0.0, 1.0 RGB
@property(class, nonatomic, readonly) UIColor *orangeColor;     // 1.0, 0.5, 0.0 RGB
@property(class, nonatomic, readonly) UIColor *purpleColor;     // 0.5, 0.0, 0.5 RGB
@property(class, nonatomic, readonly) UIColor *brownColor;      // 0.6, 0.4, 0.2 RGB
@property(class, nonatomic, readonly) UIColor *clearColor;      // 0.0 white, 0.0 alpha
#else
+ (UIColor *)blackColor;      // 0.0 white
+ (UIColor *)darkGrayColor;   // 0.333 white 
+ (UIColor *)lightGrayColor;  // 0.667 white 
+ (UIColor *)whiteColor;      // 1.0 white 
+ (UIColor *)grayColor;       // 0.5 white 
+ (UIColor *)redColor;        // 1.0, 0.0, 0.0 RGB 
+ (UIColor *)greenColor;      // 0.0, 1.0, 0.0 RGB 
+ (UIColor *)blueColor;       // 0.0, 0.0, 1.0 RGB 
+ (UIColor *)cyanColor;       // 0.0, 1.0, 1.0 RGB 
+ (UIColor *)yellowColor;     // 1.0, 1.0, 0.0 RGB 
+ (UIColor *)magentaColor;    // 1.0, 0.0, 1.0 RGB 
+ (UIColor *)orangeColor;     // 1.0, 0.5, 0.0 RGB 
+ (UIColor *)purpleColor;     // 0.5, 0.0, 0.5 RGB 
+ (UIColor *)brownColor;      // 0.6, 0.4, 0.2 RGB 
+ (UIColor *)clearColor;      // 0.0 white, 0.0 alpha 
#endif

// Set the color: Sets the fill and stroke colors in the current drawing context. Should be implemented by subclassers.
- (void)set;

// Set the fill or stroke colors individually. These should be implemented by subclassers.
- (void)setFill;
- (void)setStroke;

// Convenience methods for getting components.
// If the receiver is of a compatible color space, any non-NULL parameters are populated and 'YES' is returned. Otherwise, the parameters are left unchanged and 'NO' is returned.
- (BOOL)getWhite:(nullable CGFloat *)white alpha:(nullable CGFloat *)alpha NS_AVAILABLE_IOS(5_0);
- (BOOL)getHue:(nullable CGFloat *)hue saturation:(nullable CGFloat *)saturation brightness:(nullable CGFloat *)brightness alpha:(nullable CGFloat *)alpha NS_AVAILABLE_IOS(5_0);
- (BOOL)getRed:(nullable CGFloat *)red green:(nullable CGFloat *)green blue:(nullable CGFloat *)blue alpha:(nullable CGFloat *)alpha NS_AVAILABLE_IOS(5_0);

// Returns a color in the same color space as the receiver with the specified alpha component.
- (UIColor *)colorWithAlphaComponent:(CGFloat)alpha;

// Access the underlying CGColor or CIColor.
@property(nonatomic,readonly) CGColorRef CGColor;
- (CGColorRef)CGColor NS_RETURNS_INNER_POINTER CF_RETURNS_NOT_RETAINED;
#if __has_include(<CoreImage/CoreImage.h>)
@property(nonatomic,readonly) CIColor   *CIColor NS_AVAILABLE_IOS(5_0);
#endif

@end


@interface UIColor (UINSItemProvider) <NSItemProviderReading, NSItemProviderWriting>

@end


#if __has_include(<CoreImage/CoreImage.h>)
@interface CIColor(UIKitAdditions)

- (instancetype)initWithColor:(UIColor *)color NS_AVAILABLE_IOS(5_0);

@end
#endif

@interface UIColor (UIColorNamedColors)
+ (nullable UIColor *)colorNamed:(NSString *)name NS_AVAILABLE_IOS(11_0);      // load from main bundle
+ (nullable UIColor *)colorNamed:(NSString *)name inBundle:(nullable NSBundle *)bundle compatibleWithTraitCollection:(nullable UITraitCollection *)traitCollection NS_AVAILABLE_IOS(11_0);
@end

NS_ASSUME_NONNULL_END
