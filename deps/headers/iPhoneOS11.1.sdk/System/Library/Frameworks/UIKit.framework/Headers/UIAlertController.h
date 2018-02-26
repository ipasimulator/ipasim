//
//  UIAlertController.h
//  UIKit
//
//  Copyright (c) 2014-2017 Apple Inc. All rights reserved.
//

#import <UIKit/UIViewController.h>
#import <UIKit/UISpringLoadedInteractionSupporting.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, UIAlertActionStyle) {
    UIAlertActionStyleDefault = 0,
    UIAlertActionStyleCancel,
    UIAlertActionStyleDestructive
} NS_ENUM_AVAILABLE_IOS(8_0);

typedef NS_ENUM(NSInteger, UIAlertControllerStyle) {
    UIAlertControllerStyleActionSheet = 0,
    UIAlertControllerStyleAlert
} NS_ENUM_AVAILABLE_IOS(8_0);

NS_CLASS_AVAILABLE_IOS(8_0) @interface UIAlertAction : NSObject <NSCopying>

+ (instancetype)actionWithTitle:(nullable NSString *)title style:(UIAlertActionStyle)style handler:(void (^ __nullable)(UIAlertAction *action))handler;

@property (nullable, nonatomic, readonly) NSString *title;
@property (nonatomic, readonly) UIAlertActionStyle style;
@property (nonatomic, getter=isEnabled) BOOL enabled;

@end

NS_CLASS_AVAILABLE_IOS(8_0) @interface UIAlertController : UIViewController

+ (instancetype)alertControllerWithTitle:(nullable NSString *)title message:(nullable NSString *)message preferredStyle:(UIAlertControllerStyle)preferredStyle;

- (void)addAction:(UIAlertAction *)action;
@property (nonatomic, readonly) NSArray<UIAlertAction *> *actions;

@property (nonatomic, strong, nullable) UIAlertAction *preferredAction NS_AVAILABLE_IOS(9_0);

- (void)addTextFieldWithConfigurationHandler:(void (^ __nullable)(UITextField *textField))configurationHandler;
@property (nullable, nonatomic, readonly) NSArray<UITextField *> *textFields;

@property (nullable, nonatomic, copy) NSString *title;
@property (nullable, nonatomic, copy) NSString *message;

@property (nonatomic, readonly) UIAlertControllerStyle preferredStyle;

@end

#if TARGET_OS_IOS
@interface UIAlertController (SpringLoading) <UISpringLoadedInteractionSupporting>
@end
#endif

NS_ASSUME_NONNULL_END
