//
//  UIStringDrawing.h
//  UIKit
//
//  Copyright (c) 2005-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>
#if (TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR)
#import <CoreGraphics/CoreGraphics.h>
#endif
#import <UIKit/NSParagraphStyle.h>
#import <UIKit/NSText.h>

/* Keys for text attributes dictionaries.
 These keys are superseded by the corresponding attribute name keys (NSFontAttributeName, NSForegroundColorAttributeName, NSShadowAttributeName)
 in NSAttributedString.h.
 */
// Key to the font in the text attributes dictionary. A UIFont instance is expected. Use a font with size 0.0 to get the default font size for the situation.
UIKIT_EXTERN NSString *const UITextAttributeFont NS_DEPRECATED_IOS(5_0, 7_0, "Use NSFontAttributeName") __TVOS_PROHIBITED;
// Key to the text color in the text attributes dictionary. A UIColor instance is expected.
UIKIT_EXTERN NSString *const UITextAttributeTextColor NS_DEPRECATED_IOS(5_0, 7_0, "Use NSForegroundColorAttributeName") __TVOS_PROHIBITED;
// Key to the text shadow color in the text attributes dictionary.  A UIColor instance is expected.
UIKIT_EXTERN NSString *const UITextAttributeTextShadowColor NS_DEPRECATED_IOS(5_0, 7_0, "Use NSShadowAttributeName with an NSShadow instance as the value") __TVOS_PROHIBITED;
// Key to the offset used for the text shadow in the text attributes dictionary. An NSValue instance wrapping a UIOffset struct is expected.
UIKIT_EXTERN NSString *const UITextAttributeTextShadowOffset NS_DEPRECATED_IOS(5_0, 7_0, "Use NSShadowAttributeName with an NSShadow instance as the value") __TVOS_PROHIBITED;

// Deprecated: use NSLineBreakMode instead
typedef NS_ENUM(NSInteger, UILineBreakMode) {
    UILineBreakModeWordWrap = 0,            // Wrap at word boundaries
    UILineBreakModeCharacterWrap,           // Wrap at character boundaries
    UILineBreakModeClip,                    // Simply clip when it hits the end of the rect
    UILineBreakModeHeadTruncation,          // Truncate at head of line: "...wxyz". Will truncate multiline text on first line
    UILineBreakModeTailTruncation,          // Truncate at tail of line: "abcd...". Will truncate multiline text on last line
    UILineBreakModeMiddleTruncation,        // Truncate middle of line:  "ab...yz". Will truncate multiline text in the middle
} NS_DEPRECATED_IOS(2_0,6_0) __TVOS_PROHIBITED;

// Deprecated: use NSTextAlignment enum in UIKit/NSText.h
typedef NS_ENUM(NSInteger, UITextAlignment) {
    UITextAlignmentLeft = 0,
    UITextAlignmentCenter,
    UITextAlignmentRight,                   // could add justified in future
} NS_DEPRECATED_IOS(2_0,6_0) __TVOS_PROHIBITED;

typedef NS_ENUM(NSInteger, UIBaselineAdjustment) {
    UIBaselineAdjustmentAlignBaselines = 0, // default. used when shrinking text to position based on the original baseline
    UIBaselineAdjustmentAlignCenters,
    UIBaselineAdjustmentNone,
};

@class UIFont;

// these methods draw using a UIFont. draw methods return size of actual string. all draw in the current context using the current color

@interface NSString(UIStringDrawing)

// Single line, no wrapping. Truncation based on the NSLineBreakMode.
- (CGSize)sizeWithFont:(UIFont *)font NS_DEPRECATED_IOS(2_0, 7_0, "Use -sizeWithAttributes:") __TVOS_PROHIBITED;
- (CGSize)sizeWithFont:(UIFont *)font forWidth:(CGFloat)width lineBreakMode:(NSLineBreakMode)lineBreakMode NS_DEPRECATED_IOS(2_0, 7_0, "Use -boundingRectWithSize:options:attributes:context:") __TVOS_PROHIBITED;

// Single line, no wrapping. Truncation based on the NSLineBreakMode.
- (CGSize)drawAtPoint:(CGPoint)point withFont:(UIFont *)font NS_DEPRECATED_IOS(2_0, 7_0, "Use -drawAtPoint:withAttributes:") __TVOS_PROHIBITED;
- (CGSize)drawAtPoint:(CGPoint)point forWidth:(CGFloat)width withFont:(UIFont *)font lineBreakMode:(NSLineBreakMode)lineBreakMode  NS_DEPRECATED_IOS(2_0, 7_0, "Use -drawInRect:withAttributes:") __TVOS_PROHIBITED;

// Wrapping to fit horizontal and vertical size. Text will be wrapped and truncated using the NSLineBreakMode. If the height is less than a line of text, it may return
// a vertical size that is bigger than the one passed in.
// If you size your text using the constrainedToSize: methods below, you should draw the text using the drawInRect: methods using the same line break mode for consistency
- (CGSize)sizeWithFont:(UIFont *)font constrainedToSize:(CGSize)size NS_DEPRECATED_IOS(2_0, 7_0, "Use -boundingRectWithSize:options:attributes:context:") __TVOS_PROHIBITED; // Uses NSLineBreakModeWordWrap
- (CGSize)sizeWithFont:(UIFont *)font constrainedToSize:(CGSize)size lineBreakMode:(NSLineBreakMode)lineBreakMode NS_DEPRECATED_IOS(2_0, 7_0, "Use -boundingRectWithSize:options:attributes:context:") __TVOS_PROHIBITED; // NSTextAlignment is not needed to determine size

// Wrapping to fit horizontal and vertical size.
- (CGSize)drawInRect:(CGRect)rect withFont:(UIFont *)font NS_DEPRECATED_IOS(2_0, 7_0, "Use -drawInRect:withAttributes:") __TVOS_PROHIBITED;
- (CGSize)drawInRect:(CGRect)rect withFont:(UIFont *)font lineBreakMode:(NSLineBreakMode)lineBreakMode NS_DEPRECATED_IOS(2_0, 7_0, "Use -drawInRect:withAttributes:") __TVOS_PROHIBITED;
- (CGSize)drawInRect:(CGRect)rect withFont:(UIFont *)font lineBreakMode:(NSLineBreakMode)lineBreakMode alignment:(NSTextAlignment)alignment NS_DEPRECATED_IOS(2_0, 7_0, "Use -drawInRect:withAttributes:") __TVOS_PROHIBITED;

// These methods will behave identically to the above single line methods if the string will fit in the specified width in the specified font.
// If not, the font size will be reduced until either the string fits or the minimum font size is reached.  If the minimum font
// size is reached and the string still won't fit, the string will be truncated and drawn at the minimum font size.
// The first two methods are used together, and the actualFontSize returned in the sizeWithFont method should be passed to the drawAtPoint method.
// The last method will do the sizing calculation and drawing in one operation.
- (CGSize)sizeWithFont:(UIFont *)font minFontSize:(CGFloat)minFontSize actualFontSize:(CGFloat *)actualFontSize forWidth:(CGFloat)width lineBreakMode:(NSLineBreakMode)lineBreakMode NS_DEPRECATED_IOS(2_0, 7_0) __TVOS_PROHIBITED;

- (CGSize)drawAtPoint:(CGPoint)point forWidth:(CGFloat)width withFont:(UIFont *)font fontSize:(CGFloat)fontSize lineBreakMode:(NSLineBreakMode)lineBreakMode baselineAdjustment:(UIBaselineAdjustment)baselineAdjustment NS_DEPRECATED_IOS(2_0, 7_0, "Use -drawInRect:withAttributes:") __TVOS_PROHIBITED;

- (CGSize)drawAtPoint:(CGPoint)point forWidth:(CGFloat)width withFont:(UIFont *)font minFontSize:(CGFloat)minFontSize actualFontSize:(CGFloat *)actualFontSize lineBreakMode:(NSLineBreakMode)lineBreakMode baselineAdjustment:(UIBaselineAdjustment)baselineAdjustment NS_DEPRECATED_IOS(2_0, 7_0, "Use -drawInRect:withAttributes:") __TVOS_PROHIBITED;

@end
