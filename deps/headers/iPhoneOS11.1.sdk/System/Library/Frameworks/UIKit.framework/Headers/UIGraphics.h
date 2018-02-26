//
//  UIGraphics.h
//  UIKit
//
//  Copyright (c) 2005-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class UIImage;

UIKIT_EXTERN CGContextRef __nullable UIGraphicsGetCurrentContext(void) CF_RETURNS_NOT_RETAINED;
UIKIT_EXTERN void UIGraphicsPushContext(CGContextRef context);
UIKIT_EXTERN void UIGraphicsPopContext(void);

UIKIT_EXTERN void UIRectFillUsingBlendMode(CGRect rect, CGBlendMode blendMode);
UIKIT_EXTERN void UIRectFill(CGRect rect);

UIKIT_EXTERN void UIRectFrameUsingBlendMode(CGRect rect, CGBlendMode blendMode);
UIKIT_EXTERN void UIRectFrame(CGRect rect);

UIKIT_EXTERN void UIRectClip(CGRect rect);

// UIImage context

// The following methods will only return a 8-bit per channel context in the DeviceRGB color space.
// Any new bitmap drawing code is encouraged to use UIGraphicsImageRenderer in leiu of this API.
UIKIT_EXTERN void     UIGraphicsBeginImageContext(CGSize size);
UIKIT_EXTERN void     UIGraphicsBeginImageContextWithOptions(CGSize size, BOOL opaque, CGFloat scale) NS_AVAILABLE_IOS(4_0);
UIKIT_EXTERN UIImage* __nullable UIGraphicsGetImageFromCurrentImageContext(void);
UIKIT_EXTERN void     UIGraphicsEndImageContext(void); 

// PDF context

UIKIT_EXTERN BOOL UIGraphicsBeginPDFContextToFile(NSString *path, CGRect bounds, NSDictionary * __nullable documentInfo) NS_AVAILABLE_IOS(3_2);
UIKIT_EXTERN void UIGraphicsBeginPDFContextToData(NSMutableData *data, CGRect bounds, NSDictionary * __nullable documentInfo) NS_AVAILABLE_IOS(3_2);
UIKIT_EXTERN void UIGraphicsEndPDFContext(void) NS_AVAILABLE_IOS(3_2);

UIKIT_EXTERN void UIGraphicsBeginPDFPage(void) NS_AVAILABLE_IOS(3_2);
UIKIT_EXTERN void UIGraphicsBeginPDFPageWithInfo(CGRect bounds, NSDictionary * __nullable pageInfo) NS_AVAILABLE_IOS(3_2);

UIKIT_EXTERN CGRect UIGraphicsGetPDFContextBounds(void) NS_AVAILABLE_IOS(3_2);

UIKIT_EXTERN void UIGraphicsSetPDFContextURLForRect(NSURL *url, CGRect rect) NS_AVAILABLE_IOS(3_2);
UIKIT_EXTERN void UIGraphicsAddPDFContextDestinationAtPoint(NSString *name, CGPoint point) NS_AVAILABLE_IOS(3_2);
UIKIT_EXTERN void UIGraphicsSetPDFContextDestinationForRect(NSString *name, CGRect rect) NS_AVAILABLE_IOS(3_2);

NS_ASSUME_NONNULL_END
