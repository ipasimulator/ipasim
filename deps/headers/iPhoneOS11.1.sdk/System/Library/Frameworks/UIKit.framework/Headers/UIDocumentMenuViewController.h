//
//  UIDocumentMenuViewController.h
//  UIKit
//
//  Copyright (c) 2014-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIViewController.h>
#import <UIKit/UIDocumentPickerViewController.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, UIDocumentMenuOrder) {
    UIDocumentMenuOrderFirst,
    UIDocumentMenuOrderLast
} NS_ENUM_DEPRECATED_IOS(8_0,11_0) __TVOS_PROHIBITED;

__TVOS_PROHIBITED @protocol UIDocumentMenuDelegate <NSObject>

- (void)documentMenu:(UIDocumentMenuViewController *)documentMenu didPickDocumentPicker:(UIDocumentPickerViewController *)documentPicker;
@optional
- (void)documentMenuWasCancelled:(UIDocumentMenuViewController *)documentMenu;

@end

NS_CLASS_DEPRECATED_IOS(8_0, 11_0, "UIDocumentMenuViewController is deprecated. Use UIDocumentPickerViewController directly.")
__TVOS_PROHIBITED @interface UIDocumentMenuViewController : UIViewController

- (instancetype)initWithDocumentTypes:(NSArray <NSString *> *)allowedUTIs inMode:(UIDocumentPickerMode)mode NS_DESIGNATED_INITIALIZER;
- (instancetype)initWithURL:(NSURL *)url inMode:(UIDocumentPickerMode)mode NS_DESIGNATED_INITIALIZER;
- (nullable instancetype)initWithCoder:(NSCoder *)aDecoder NS_DESIGNATED_INITIALIZER;

- (void)addOptionWithTitle:(NSString *)title image:(nullable UIImage *)image order:(UIDocumentMenuOrder)order handler:(void (^)(void))handler;

@property (nullable, nonatomic, weak) id<UIDocumentMenuDelegate> delegate;

@end

NS_ASSUME_NONNULL_END
