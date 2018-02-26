//
//  UIAlertView.h
//  UIKit
//
//  Copyright 2010-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>
#import <UIKit/UITextField.h>
#import <UIKit/UIView.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, UIAlertViewStyle) {
    UIAlertViewStyleDefault = 0,
    UIAlertViewStyleSecureTextInput,
    UIAlertViewStylePlainTextInput,
    UIAlertViewStyleLoginAndPasswordInput
} __TVOS_PROHIBITED;

@protocol UIAlertViewDelegate;
@class UILabel, UIToolbar, UITabBar, UIWindow, UIBarButtonItem, UIPopoverController;

NS_CLASS_DEPRECATED_IOS(2_0, 9_0, "UIAlertView is deprecated. Use UIAlertController with a preferredStyle of UIAlertControllerStyleAlert instead") __TVOS_PROHIBITED
@interface UIAlertView : UIView

- (instancetype)initWithTitle:(nullable NSString *)title message:(nullable NSString *)message delegate:(nullable id /*<UIAlertViewDelegate>*/)delegate cancelButtonTitle:(nullable NSString *)cancelButtonTitle otherButtonTitles:(nullable NSString *)otherButtonTitles, ... NS_REQUIRES_NIL_TERMINATION NS_EXTENSION_UNAVAILABLE_IOS("Use UIAlertController instead.");

- (id)initWithFrame:(CGRect)frame NS_DESIGNATED_INITIALIZER;
- (nullable instancetype) initWithCoder:(nonnull NSCoder *)aDecoder NS_DESIGNATED_INITIALIZER;

@property(nullable,nonatomic,weak) id /*<UIAlertViewDelegate>*/ delegate;
@property(nonatomic,copy) NSString *title;
@property(nullable,nonatomic,copy) NSString *message;   // secondary explanation text


// adds a button with the title. returns the index (0 based) of where it was added. buttons are displayed in the order added except for the
// cancel button which will be positioned based on HI requirements. buttons cannot be customized.
- (NSInteger)addButtonWithTitle:(nullable NSString *)title;    // returns index of button. 0 based.
- (nullable NSString *)buttonTitleAtIndex:(NSInteger)buttonIndex;
@property(nonatomic,readonly) NSInteger numberOfButtons;
@property(nonatomic) NSInteger cancelButtonIndex;      // if the delegate does not implement -alertViewCancel:, we pretend this button was clicked on. default is -1

@property(nonatomic,readonly) NSInteger firstOtherButtonIndex;	// -1 if no otherButtonTitles or initWithTitle:... not used
@property(nonatomic,readonly,getter=isVisible) BOOL visible;

// shows popup alert animated.
- (void)show;

// hides alert sheet or popup. use this method when you need to explicitly dismiss the alert.
// it does not need to be called if the user presses on a button
- (void)dismissWithClickedButtonIndex:(NSInteger)buttonIndex animated:(BOOL)animated;

// Alert view style - defaults to UIAlertViewStyleDefault
@property(nonatomic,assign) UIAlertViewStyle alertViewStyle NS_AVAILABLE_IOS(5_0);

// Retrieve a text field at an index
// The field at index 0 will be the first text field (the single field or the login field), the field at index 1 will be the password field. */
- (nullable UITextField *)textFieldAtIndex:(NSInteger)textFieldIndex NS_AVAILABLE_IOS(5_0);


@end

__TVOS_PROHIBITED
@protocol UIAlertViewDelegate <NSObject>
@optional

// Called when a button is clicked. The view will be automatically dismissed after this call returns
- (void)alertView:(UIAlertView *)alertView clickedButtonAtIndex:(NSInteger)buttonIndex NS_DEPRECATED_IOS(2_0, 9_0);

// Called when we cancel a view (eg. the user clicks the Home button). This is not called when the user clicks the cancel button.
// If not defined in the delegate, we simulate a click in the cancel button
- (void)alertViewCancel:(UIAlertView *)alertView NS_DEPRECATED_IOS(2_0, 9_0);

- (void)willPresentAlertView:(UIAlertView *)alertView NS_DEPRECATED_IOS(2_0, 9_0);  // before animation and showing view
- (void)didPresentAlertView:(UIAlertView *)alertView NS_DEPRECATED_IOS(2_0, 9_0);  // after animation

- (void)alertView:(UIAlertView *)alertView willDismissWithButtonIndex:(NSInteger)buttonIndex NS_DEPRECATED_IOS(2_0, 9_0); // before animation and hiding view
- (void)alertView:(UIAlertView *)alertView didDismissWithButtonIndex:(NSInteger)buttonIndex NS_DEPRECATED_IOS(2_0, 9_0);  // after animation

// Called after edits in any of the default fields added by the style
- (BOOL)alertViewShouldEnableFirstOtherButton:(UIAlertView *)alertView NS_DEPRECATED_IOS(2_0, 9_0);

@end

NS_ASSUME_NONNULL_END
