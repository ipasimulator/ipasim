//
//  UIPrintError.h
//  UIKit
//
//  Copyright 2010-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

UIKIT_EXTERN NSErrorDomain const UIPrintErrorDomain __TVOS_PROHIBITED;

enum {
    UIPrintingNotAvailableError = 1,  // cannot print at this time
    UIPrintNoContentError,            // empty list of files or images
    UIPrintUnknownImageFormatError,   // unrecognized image format
    UIPrintJobFailedError,            // internal error with print job
} __TVOS_PROHIBITED;

NS_ASSUME_NONNULL_END
