//
//  FPUIActionExtensionViewController.h
//  FileProviderUI
//
//  Copyright © 2016 Apple Inc. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <FileProvider/FileProvider.h>

#import <FileProviderUI/FPUIBase.h>
#import <FileProviderUI/FPUIActionExtensionContext.h>


NS_ASSUME_NONNULL_BEGIN

FPUI_AVAILABLE @interface FPUIActionExtensionViewController : UIViewController

@property (nonatomic, readonly, strong) FPUIActionExtensionContext *extensionContext;

// To be overridden by the subclass
- (void)prepareForError:(NSError *)error NS_SWIFT_NAME( prepare(forError:) );

// To be overridden by the subclass
- (void)prepareForActionWithIdentifier:(NSString *)actionIdentifier itemIdentifiers:(NSArray <NSFileProviderItemIdentifier> *)itemIdentifiers NS_SWIFT_NAME( prepare(forAction:itemIdentifiers:) );
    
@end

NS_ASSUME_NONNULL_END
