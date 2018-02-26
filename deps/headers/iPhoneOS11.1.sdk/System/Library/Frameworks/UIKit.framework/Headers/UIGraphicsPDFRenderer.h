//
//  UIGraphicsPDFRenderer.h
//  UIKit
//
//  Copyright (c) 2016-2017 Apple Inc. All rights reserved.
//

#import <UIKit/UIGraphicsRenderer.h>

NS_ASSUME_NONNULL_BEGIN

@class UIGraphicsPDFRendererContext;

typedef void (^UIGraphicsPDFDrawingActions)(UIGraphicsPDFRendererContext *rendererContext) NS_AVAILABLE_IOS(10_0);

NS_CLASS_AVAILABLE_IOS(10_0) @interface UIGraphicsPDFRendererFormat : UIGraphicsRendererFormat
@property (nonatomic, copy) NSDictionary<NSString *, id> *documentInfo;
@end

NS_CLASS_AVAILABLE_IOS(10_0) @interface UIGraphicsPDFRendererContext : UIGraphicsRendererContext
@property (nonatomic, readonly) CGRect pdfContextBounds;

- (void)beginPage;
- (void)beginPageWithBounds:(CGRect)bounds pageInfo:(NSDictionary<NSString *, id> *)pageInfo;

- (void)setURL:(NSURL *)url forRect:(CGRect)rect;
- (void)addDestinationWithName:(NSString *)name atPoint:(CGPoint)point;
- (void)setDestinationWithName:(NSString *)name forRect:(CGRect)rect;
@end

NS_CLASS_AVAILABLE_IOS(10_0) @interface UIGraphicsPDFRenderer : UIGraphicsRenderer
- (instancetype)initWithBounds:(CGRect)bounds format:(UIGraphicsPDFRendererFormat *)format NS_DESIGNATED_INITIALIZER;

- (BOOL)writePDFToURL:(NSURL *)url withActions:(NS_NOESCAPE UIGraphicsPDFDrawingActions)actions error:(NSError **)error;
- (NSData *)PDFDataWithActions:(NS_NOESCAPE UIGraphicsPDFDrawingActions)actions;
@end

NS_ASSUME_NONNULL_END
