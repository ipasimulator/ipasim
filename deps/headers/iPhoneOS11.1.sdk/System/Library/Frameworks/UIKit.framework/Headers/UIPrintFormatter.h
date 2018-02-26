//
//  UIPrintFormatter.h
//  UIKit
//
//  Copyright 2010-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UIKit/UIView.h>
#import <UIKit/UIStringDrawing.h>
#import <UIKit/UIGeometry.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class UIPrintPageRenderer;
@class UIView, UIFont, UIColor;

NS_CLASS_AVAILABLE_IOS(4_2) __TVOS_PROHIBITED @interface UIPrintFormatter : NSObject <NSCopying>

@property(nullable,nonatomic,readonly,weak) UIPrintPageRenderer *printPageRenderer __TVOS_PROHIBITED; // default is nil. set when formatter added to a print page renderer
- (void)removeFromPrintPageRenderer __TVOS_PROHIBITED;

@property(nonatomic) CGFloat      maximumContentHeight __TVOS_PROHIBITED;      // default is 0.0. limits content to width
@property(nonatomic) CGFloat      maximumContentWidth __TVOS_PROHIBITED;       // default is 0.0. limits content to height
@property(nonatomic) UIEdgeInsets contentInsets NS_DEPRECATED_IOS(4_2,10_0, "Use perPageContentInsets instead.") __TVOS_PROHIBITED;
                                                                               // default is UIEdgeInsetsZero. from edge of printableRect. applies to whole content. bottom inset unused
                                                                               // Deprecated in favor of perPageContentInsets which produces better output
@property(nonatomic) UIEdgeInsets perPageContentInsets __TVOS_PROHIBITED;      // default is UIEdgeInsetsZero from edge of the page.  applies to content on each page (each edge applies to each page)

@property(nonatomic)          NSInteger startPage __TVOS_PROHIBITED;           // default is NSNotFound
@property(nonatomic,readonly) NSInteger pageCount __TVOS_PROHIBITED;           // calculated

- (CGRect)rectForPageAtIndex:(NSInteger)pageIndex __TVOS_PROHIBITED;                     // returns empty rect if index out of range
- (void)drawInRect:(CGRect)rect forPageAtIndex:(NSInteger)pageIndex __TVOS_PROHIBITED;   // override point to add custom drawing

@end

//______________________________

NS_CLASS_AVAILABLE_IOS(4_2) __TVOS_PROHIBITED @interface UISimpleTextPrintFormatter : UIPrintFormatter {
}

- (instancetype)initWithText:(NSString *)text;
- (instancetype)initWithAttributedText:(NSAttributedString *)attributedText NS_AVAILABLE_IOS(7_0);

@property(nullable,nonatomic,copy)     NSString       *text;                   // cannot change once drawing started
@property(nullable,nonatomic,copy)     NSAttributedString *attributedText NS_AVAILABLE_IOS(7_0);
@property(nullable,nonatomic,strong)   UIFont         *font;
@property(nullable,nonatomic,strong)   UIColor        *color;
@property(nonatomic)          NSTextAlignment textAlignment;

@end

//______________________________

NS_CLASS_AVAILABLE_IOS(4_2) __TVOS_PROHIBITED @interface UIMarkupTextPrintFormatter : UIPrintFormatter {
}

- (instancetype)initWithMarkupText:(NSString *)markupText;
@property(nullable,nonatomic,copy) NSString *markupText;                    // cannot change once drawing started

@end

//______________________________

NS_CLASS_AVAILABLE_IOS(4_2) __TVOS_PROHIBITED @interface UIViewPrintFormatter : UIPrintFormatter 

@property(nonatomic,readonly) UIView *view;

@end

//______________________________

@interface UIView(UIPrintFormatter)

- (UIViewPrintFormatter *)viewPrintFormatter __TVOS_PROHIBITED;                                          // returns a new print formatter each time
- (void)drawRect:(CGRect)rect forViewPrintFormatter:(UIViewPrintFormatter *)formatter __TVOS_PROHIBITED;     // default calls -drawRect:

@end

NS_ASSUME_NONNULL_END
