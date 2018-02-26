//
//  UIImage.h
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
#import <UIKit/UIColor.h>
#import <UIKit/UIGeometry.h>
#import <UIKit/NSItemProvider+UIKitAdditions.h>

NS_ASSUME_NONNULL_BEGIN

#if __has_include(<UIKit/UITraitCollection.h>)
@class UITraitCollection, UIImageAsset;
#endif

#if __has_include(<UIKit/UIGraphicsImageRenderer.h>)
@class UIGraphicsImageRendererFormat;
#endif

typedef NS_ENUM(NSInteger, UIImageOrientation) {
    UIImageOrientationUp,            // default orientation
    UIImageOrientationDown,          // 180 deg rotation
    UIImageOrientationLeft,          // 90 deg CCW
    UIImageOrientationRight,         // 90 deg CW
    UIImageOrientationUpMirrored,    // as above but image mirrored along other axis. horizontal flip
    UIImageOrientationDownMirrored,  // horizontal flip
    UIImageOrientationLeftMirrored,  // vertical flip
    UIImageOrientationRightMirrored, // vertical flip
};

/* UIImage will implement the resizing mode the fastest way possible while
 retaining the desired visual appearance.
 Note that if an image's resizable area is one point then UIImageResizingModeTile
 is visually indistinguishable from UIImageResizingModeStretch.
 */
typedef NS_ENUM(NSInteger, UIImageResizingMode) {
    UIImageResizingModeTile,
    UIImageResizingModeStretch,
};

/* Images are created with UIImageRenderingModeAutomatic by default. An image with this mode is interpreted as a template image or an original image based on the context in which it is rendered. For example, navigation bars, tab bars, toolbars, and segmented controls automatically treat their foreground images as templates, while image views and web views treat their images as originals. You can use UIImageRenderingModeAlwaysTemplate to force your image to always be rendered as a template or UIImageRenderingModeAlwaysOriginal to force your image to always be rendered as an original.
 */
typedef NS_ENUM(NSInteger, UIImageRenderingMode) {
    UIImageRenderingModeAutomatic,          // Use the default rendering mode for the context where the image is used
    
    UIImageRenderingModeAlwaysOriginal,     // Always draw the original image, without treating it as a template
    UIImageRenderingModeAlwaysTemplate,     // Always draw the image as a template image, ignoring its color information
} NS_ENUM_AVAILABLE_IOS(7_0);

NS_CLASS_AVAILABLE_IOS(2_0) @interface UIImage : NSObject <NSSecureCoding> 

+ (nullable UIImage *)imageNamed:(NSString *)name;      // load from main bundle
#if __has_include(<UIKit/UITraitCollection.h>)
+ (nullable UIImage *)imageNamed:(NSString *)name inBundle:(nullable NSBundle *)bundle compatibleWithTraitCollection:(nullable UITraitCollection *)traitCollection NS_AVAILABLE_IOS(8_0);
#endif

+ (nullable UIImage *)imageWithContentsOfFile:(NSString *)path;
+ (nullable UIImage *)imageWithData:(NSData *)data;
+ (nullable UIImage *)imageWithData:(NSData *)data scale:(CGFloat)scale NS_AVAILABLE_IOS(6_0);
+ (UIImage *)imageWithCGImage:(CGImageRef)cgImage;
+ (UIImage *)imageWithCGImage:(CGImageRef)cgImage scale:(CGFloat)scale orientation:(UIImageOrientation)orientation NS_AVAILABLE_IOS(4_0);
#if __has_include(<CoreImage/CoreImage.h>)
+ (UIImage *)imageWithCIImage:(CIImage *)ciImage NS_AVAILABLE_IOS(5_0);
+ (UIImage *)imageWithCIImage:(CIImage *)ciImage scale:(CGFloat)scale orientation:(UIImageOrientation)orientation NS_AVAILABLE_IOS(6_0);
#endif

- (nullable instancetype)initWithContentsOfFile:(NSString *)path;
- (nullable instancetype)initWithData:(NSData *)data;
- (nullable instancetype)initWithData:(NSData *)data scale:(CGFloat)scale NS_AVAILABLE_IOS(6_0);
- (instancetype)initWithCGImage:(CGImageRef)cgImage;
- (instancetype)initWithCGImage:(CGImageRef)cgImage scale:(CGFloat)scale orientation:(UIImageOrientation)orientation NS_AVAILABLE_IOS(4_0);
#if __has_include(<CoreImage/CoreImage.h>)
- (instancetype)initWithCIImage:(CIImage *)ciImage NS_AVAILABLE_IOS(5_0);
- (instancetype)initWithCIImage:(CIImage *)ciImage scale:(CGFloat)scale orientation:(UIImageOrientation)orientation NS_AVAILABLE_IOS(6_0);
#endif

@property(nonatomic,readonly) CGSize size; // reflects orientation setting. In iOS 4.0 and later, this is measured in points. In 3.x and earlier, measured in pixels
@property(nullable, nonatomic,readonly) CGImageRef CGImage; // returns underlying CGImageRef or nil if CIImage based
- (nullable CGImageRef)CGImage NS_RETURNS_INNER_POINTER CF_RETURNS_NOT_RETAINED;
#if __has_include(<CoreImage/CoreImage.h>)
@property(nullable,nonatomic,readonly) CIImage *CIImage NS_AVAILABLE_IOS(5_0); // returns underlying CIImage or nil if CGImageRef based
#endif
@property(nonatomic,readonly) UIImageOrientation imageOrientation; // this will affect how the image is composited
@property(nonatomic,readonly) CGFloat scale NS_AVAILABLE_IOS(4_0);

// animated images. When set as UIImageView.image, animation will play in an infinite loop until removed. Drawing will render the first image

+ (nullable UIImage *)animatedImageNamed:(NSString *)name duration:(NSTimeInterval)duration NS_AVAILABLE_IOS(5_0);  // read sequence of files with suffix starting at 0 or 1
+ (nullable UIImage *)animatedResizableImageNamed:(NSString *)name capInsets:(UIEdgeInsets)capInsets duration:(NSTimeInterval)duration NS_AVAILABLE_IOS(5_0); // sequence of files
+ (nullable UIImage *)animatedResizableImageNamed:(NSString *)name capInsets:(UIEdgeInsets)capInsets resizingMode:(UIImageResizingMode)resizingMode duration:(NSTimeInterval)duration NS_AVAILABLE_IOS(6_0);
+ (nullable UIImage *)animatedImageWithImages:(NSArray<UIImage *> *)images duration:(NSTimeInterval)duration NS_AVAILABLE_IOS(5_0);

@property(nullable, nonatomic,readonly) NSArray<UIImage *> *images   NS_AVAILABLE_IOS(5_0); // default is nil for non-animated images
@property(nonatomic,readonly) NSTimeInterval duration NS_AVAILABLE_IOS(5_0); // total duration for all frames. default is 0 for non-animated images

// the these draw the image 'right side up' in the usual coordinate system with 'point' being the top-left.

- (void)drawAtPoint:(CGPoint)point;                                                        // mode = kCGBlendModeNormal, alpha = 1.0
- (void)drawAtPoint:(CGPoint)point blendMode:(CGBlendMode)blendMode alpha:(CGFloat)alpha;
- (void)drawInRect:(CGRect)rect;                                                           // mode = kCGBlendModeNormal, alpha = 1.0
- (void)drawInRect:(CGRect)rect blendMode:(CGBlendMode)blendMode alpha:(CGFloat)alpha;

- (void)drawAsPatternInRect:(CGRect)rect; // draws the image as a CGPattern

- (UIImage *)resizableImageWithCapInsets:(UIEdgeInsets)capInsets NS_AVAILABLE_IOS(5_0); // create a resizable version of this image. the interior is tiled when drawn.
- (UIImage *)resizableImageWithCapInsets:(UIEdgeInsets)capInsets resizingMode:(UIImageResizingMode)resizingMode NS_AVAILABLE_IOS(6_0); // the interior is resized according to the resizingMode

@property(nonatomic,readonly) UIEdgeInsets capInsets               NS_AVAILABLE_IOS(5_0);   // default is UIEdgeInsetsZero for non resizable images
@property(nonatomic,readonly) UIImageResizingMode resizingMode NS_AVAILABLE_IOS(6_0); // default is UIImageResizingModeTile

// Support for constraint-based layout (auto layout)
// The alignmentRectInsets of a UIImage are used by UIImageView and other UIView and UIControl
//  subclasses that take custom images to determine the view's alignment rect insets for
//  constraint-based layout.
// The default alignmentRectInsets are UIEdgeInsetsZero.
- (UIImage *)imageWithAlignmentRectInsets:(UIEdgeInsets)alignmentInsets NS_AVAILABLE_IOS(6_0);
@property(nonatomic,readonly) UIEdgeInsets alignmentRectInsets NS_AVAILABLE_IOS(6_0);

// Create a version of this image with the specified rendering mode. By default, images have a rendering mode of UIImageRenderingModeAutomatic.
- (UIImage *)imageWithRenderingMode:(UIImageRenderingMode)renderingMode NS_AVAILABLE_IOS(7_0);
@property(nonatomic, readonly) UIImageRenderingMode renderingMode NS_AVAILABLE_IOS(7_0);

#if __has_include(<UIKit/UIGraphicsImageRenderer.h>)
// Returns an optimal UIGraphicsImageRendererFormat instance for this image, maintaining pixel format and color space.
@property (nonatomic, readonly) UIGraphicsImageRendererFormat *imageRendererFormat NS_AVAILABLE_IOS(10_0);
#endif

#if __has_include(<UIKit/UITraitCollection.h>)
@property (nonatomic, readonly, copy) UITraitCollection *traitCollection NS_AVAILABLE_IOS(8_0); // describes the image in terms of its traits
@property (nullable, nonatomic, readonly) UIImageAsset *imageAsset NS_AVAILABLE_IOS(8_0); // The asset is not encoded along with the image. Returns nil if the image is not CGImage based.
#endif

// Creates a version of this image that, when assigned to a UIImageView’s image property, draws its underlying image contents horizontally mirrored when running under a right-to-left language. Affects the flipsForRightToLeftLayoutDirection property; does not affect the imageOrientation property.
// This method cannot be used to create a left-to-right version of a right-to-left source image, and will be deprecated in a future release. New code should instead use -imageWithHorizontallyFlippedOrientation to construct a UIImageAsset.
- (UIImage *)imageFlippedForRightToLeftLayoutDirection NS_AVAILABLE_IOS(9_0);
@property (nonatomic, readonly) BOOL flipsForRightToLeftLayoutDirection NS_AVAILABLE_IOS(9_0);

// Creates a version of this image with an imageOrientation property that is horizontally mirrored from this image’s. Does not affect the flipsForRightToLeftLayoutDirection property.
- (UIImage *)imageWithHorizontallyFlippedOrientation NS_AVAILABLE_IOS(10_0);

@end

#if TARGET_OS_IOS
@interface UIImage (NSItemProvider) <NSItemProviderReading, NSItemProviderWriting, UIItemProviderPresentationSizeProviding>
#else
@interface UIImage (NSItemProvider) <NSItemProviderReading, NSItemProviderWriting>
#endif

@end


@interface UIImage(UIImageDeprecated)

// use resizableImageWithCapInsets: and capInsets.

- (UIImage *)stretchableImageWithLeftCapWidth:(NSInteger)leftCapWidth topCapHeight:(NSInteger)topCapHeight __TVOS_PROHIBITED;
@property(nonatomic,readonly) NSInteger leftCapWidth __TVOS_PROHIBITED;   // default is 0. if non-zero, horiz. stretchable. right cap is calculated as width - leftCapWidth - 1
@property(nonatomic,readonly) NSInteger topCapHeight __TVOS_PROHIBITED;   // default is 0. if non-zero, vert. stretchable. bottom cap is calculated as height - topCapWidth - 1

@end


#if __has_include(<CoreImage/CoreImage.h>)
@interface CIImage(UIKitAdditions)

- (nullable instancetype)initWithImage:(UIImage *)image NS_AVAILABLE_IOS(5_0);
- (nullable instancetype)initWithImage:(UIImage *)image options:(nullable NSDictionary *)options NS_AVAILABLE_IOS(5_0);

@end
#endif

UIKIT_EXTERN  NSData * __nullable UIImagePNGRepresentation(UIImage * __nonnull image);                               // return image as PNG. May return nil if image has no CGImageRef or invalid bitmap format
UIKIT_EXTERN  NSData * __nullable UIImageJPEGRepresentation(UIImage * __nonnull image, CGFloat compressionQuality);  // return image as JPEG. May return nil if image has no CGImageRef or invalid bitmap format. compression is 0(most)..1(least)

NS_ASSUME_NONNULL_END

