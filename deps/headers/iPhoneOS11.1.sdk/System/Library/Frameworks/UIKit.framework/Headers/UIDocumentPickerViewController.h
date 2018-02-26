//
//  UIDocumentPickerViewController.h
//  UIKit
//
//  Copyright (c) 2014-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIViewController.h>
	
NS_ASSUME_NONNULL_BEGIN

@class UIDocumentPickerViewController, UIDocumentMenuViewController;

__TVOS_PROHIBITED @protocol UIDocumentPickerDelegate <NSObject>

@optional

// Required
- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray <NSURL *>*)urls NS_AVAILABLE_IOS(11_0);

// called if the user dismisses the document picker without selecting a document (using the Cancel button)
- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller;

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentAtURL:(NSURL *)url NS_DEPRECATED_IOS(8_0, 11_0, "Implement documentPicker:didPickDocumentsAtURLs: instead");
@end

typedef NS_ENUM(NSUInteger, UIDocumentPickerMode) {
    UIDocumentPickerModeImport,
    UIDocumentPickerModeOpen,
    UIDocumentPickerModeExportToService,
    UIDocumentPickerModeMoveToService
} NS_ENUM_AVAILABLE_IOS(8_0) __TVOS_PROHIBITED;

NS_CLASS_AVAILABLE_IOS(8_0) __TVOS_PROHIBITED @interface UIDocumentPickerViewController : UIViewController

// Initializes the picker instance for selecting a document in a remote location. The valid modes are Import and Open.
- (instancetype)initWithDocumentTypes:(NSArray <NSString *>*)allowedUTIs inMode:(UIDocumentPickerMode)mode NS_DESIGNATED_INITIALIZER;
- (nullable instancetype)initWithCoder:(NSCoder *)aDecoder NS_DESIGNATED_INITIALIZER;

// Initializes the picker for exporting a local file to an external location. The valid modes are Export and Move. The new location will be returned using didPickDocumentAtURL:
- (instancetype)initWithURL:(NSURL *)url inMode:(UIDocumentPickerMode)mode NS_DESIGNATED_INITIALIZER; // This method will be deprecated in a future release and should be avoided. Instead, use initWithURLs:inMode:.

// Initializes the picker for exporting local files to an external location. The valid modes are Export and Move. The new locations will be returned using didPickDocumentAtURLs:
- (instancetype)initWithURLs:(NSArray <NSURL *> *)urls inMode:(UIDocumentPickerMode)mode NS_DESIGNATED_INITIALIZER NS_AVAILABLE_IOS(11_0);

@property (nullable, nonatomic, weak) id<UIDocumentPickerDelegate> delegate;
@property (nonatomic, assign, readonly) UIDocumentPickerMode documentPickerMode;
@property (nonatomic, assign) BOOL allowsMultipleSelection NS_AVAILABLE_IOS(11_0);

@end

NS_ASSUME_NONNULL_END
