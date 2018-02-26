//
//  UIAccessibilityZoom.h
//  UIKit
//
//  Copyright (c) 2011-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIView.h>

NS_ASSUME_NONNULL_BEGIN

/* 
 Use to inform system Zoom that focus has changed to a new location. 
 The frame should be in the coordinate space of the view.
 */
typedef NS_ENUM(NSInteger, UIAccessibilityZoomType) {
    UIAccessibilityZoomTypeInsertionPoint,      // Used when the text insertion point has moved
} NS_ENUM_AVAILABLE_IOS(5_0);

UIKIT_EXTERN void UIAccessibilityZoomFocusChanged(UIAccessibilityZoomType type, CGRect frame, UIView * __nonnull view) NS_AVAILABLE_IOS(5_0);

/*
 If your app uses multi-finger gestures that conflict with system Zoom gestures (by using three fingers), 
 calling this method will warn users of the conflict.
 */
UIKIT_EXTERN void UIAccessibilityRegisterGestureConflictWithZoom(void) NS_AVAILABLE_IOS(5_0);

NS_ASSUME_NONNULL_END
