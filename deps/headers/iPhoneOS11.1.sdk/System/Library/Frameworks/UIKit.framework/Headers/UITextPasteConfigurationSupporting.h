//
//  UITextPasteConfigurationSupporting.h
//  UIKit 
//
//  Copyright © 2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIPasteConfigurationSupporting.h>
#import <UIKit/UIPasteConfiguration.h>
#import <UIKit/UITextPasteDelegate.h>

NS_ASSUME_NONNULL_BEGIN

UIKIT_EXTERN API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, tvos)
@protocol UITextPasteConfigurationSupporting <UIPasteConfigurationSupporting>

@property (nonatomic, weak, nullable) id<UITextPasteDelegate> pasteDelegate;

@end

NS_ASSUME_NONNULL_END
