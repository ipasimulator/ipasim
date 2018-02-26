//
//  UITextView.h
//  UIKit
//
//  Copyright (c) 2007-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UIKit/UIScrollView.h>
#import <UIKit/UIStringDrawing.h>
#import <UIKit/UITextDragging.h>
#import <UIKit/UITextDropping.h>
#import <UIKit/UITextInput.h>
#import <UIKit/UIKitDefines.h>
#import <UIKit/UIDataDetectors.h>
#import <UIKit/UITextInteraction.h>
#import <UIKit/UIContentSizeCategoryAdjusting.h>
#import <UIKit/UITextPasteConfigurationSupporting.h>

NS_ASSUME_NONNULL_BEGIN

@class UIFont, UIColor, UITextView, NSTextContainer, NSLayoutManager, NSTextStorage, NSTextAttachment;

@protocol UITextViewDelegate <NSObject, UIScrollViewDelegate>

@optional

- (BOOL)textViewShouldBeginEditing:(UITextView *)textView;
- (BOOL)textViewShouldEndEditing:(UITextView *)textView;

- (void)textViewDidBeginEditing:(UITextView *)textView;
- (void)textViewDidEndEditing:(UITextView *)textView;

- (BOOL)textView:(UITextView *)textView shouldChangeTextInRange:(NSRange)range replacementText:(NSString *)text;
- (void)textViewDidChange:(UITextView *)textView;

- (void)textViewDidChangeSelection:(UITextView *)textView;

- (BOOL)textView:(UITextView *)textView shouldInteractWithURL:(NSURL *)URL inRange:(NSRange)characterRange interaction:(UITextItemInteraction)interaction NS_AVAILABLE_IOS(10_0);
- (BOOL)textView:(UITextView *)textView shouldInteractWithTextAttachment:(NSTextAttachment *)textAttachment inRange:(NSRange)characterRange interaction:(UITextItemInteraction)interaction NS_AVAILABLE_IOS(10_0);

- (BOOL)textView:(UITextView *)textView shouldInteractWithURL:(NSURL *)URL inRange:(NSRange)characterRange NS_DEPRECATED_IOS(7_0, 10_0, "Use textView:shouldInteractWithURL:inRange:forInteractionType: instead");
- (BOOL)textView:(UITextView *)textView shouldInteractWithTextAttachment:(NSTextAttachment *)textAttachment inRange:(NSRange)characterRange NS_DEPRECATED_IOS(7_0, 10_0, "Use textView:shouldInteractWithTextAttachment:inRange:forInteractionType: instead");

@end

NS_CLASS_AVAILABLE_IOS(2_0) @interface UITextView : UIScrollView <UITextInput, UIContentSizeCategoryAdjusting>

@property(nullable,nonatomic,weak) id<UITextViewDelegate> delegate;

@property(null_resettable,nonatomic,copy) NSString *text;
@property(nullable,nonatomic,strong) UIFont *font;
@property(nullable,nonatomic,strong) UIColor *textColor;
@property(nonatomic) NSTextAlignment textAlignment;    // default is NSLeftTextAlignment
@property(nonatomic) NSRange selectedRange;
@property(nonatomic,getter=isEditable) BOOL editable __TVOS_PROHIBITED;
@property(nonatomic,getter=isSelectable) BOOL selectable NS_AVAILABLE_IOS(7_0); // toggle selectability, which controls the ability of the user to select content and interact with URLs & attachments. On tvOS this also makes the text view focusable.
@property(nonatomic) UIDataDetectorTypes dataDetectorTypes NS_AVAILABLE_IOS(3_0) __TVOS_PROHIBITED;

@property(nonatomic) BOOL allowsEditingTextAttributes NS_AVAILABLE_IOS(6_0); // defaults to NO
@property(null_resettable,copy) NSAttributedString *attributedText NS_AVAILABLE_IOS(6_0);
@property(nonatomic,copy) NSDictionary<NSString *, id> *typingAttributes NS_AVAILABLE_IOS(6_0); // automatically resets when the selection changes

- (void)scrollRangeToVisible:(NSRange)range;


// Presented when object becomes first responder.  If set to nil, reverts to following responder chain.  If
// set while first responder, will not take effect until reloadInputViews is called.
@property (nullable, readwrite, strong) UIView *inputView;             
@property (nullable, readwrite, strong) UIView *inputAccessoryView;

@property(nonatomic) BOOL clearsOnInsertion NS_AVAILABLE_IOS(6_0); // defaults to NO. if YES, the selection UI is hidden, and inserting text will replace the contents of the field. changing the selection will automatically set this to NO.

// Create a new text view with the specified text container (can be nil) - this is the new designated initializer for this class
- (instancetype)initWithFrame:(CGRect)frame textContainer:(nullable NSTextContainer *)textContainer NS_AVAILABLE_IOS(7_0) NS_DESIGNATED_INITIALIZER;
- (nullable instancetype)initWithCoder:(NSCoder *)aDecoder NS_DESIGNATED_INITIALIZER;

// Get the text container for the text view
@property(nonatomic,readonly) NSTextContainer *textContainer NS_AVAILABLE_IOS(7_0);
// Inset the text container's layout area within the text view's content area
@property(nonatomic, assign) UIEdgeInsets textContainerInset NS_AVAILABLE_IOS(7_0);

// Convenience accessors (access through the text container)
@property(nonatomic,readonly) NSLayoutManager *layoutManager NS_AVAILABLE_IOS(7_0);
@property(nonatomic,readonly,strong) NSTextStorage *textStorage NS_AVAILABLE_IOS(7_0);

// Style for links
@property(null_resettable, nonatomic, copy) NSDictionary<NSString *, id> *linkTextAttributes NS_AVAILABLE_IOS(7_0);

@end

#if TARGET_OS_IOS

@interface UITextView () <UITextDraggable, UITextDroppable, UITextPasteConfigurationSupporting>
@end

#endif

UIKIT_EXTERN NSNotificationName const UITextViewTextDidBeginEditingNotification;
UIKIT_EXTERN NSNotificationName const UITextViewTextDidChangeNotification;
UIKIT_EXTERN NSNotificationName const UITextViewTextDidEndEditingNotification;

NS_ASSUME_NONNULL_END
