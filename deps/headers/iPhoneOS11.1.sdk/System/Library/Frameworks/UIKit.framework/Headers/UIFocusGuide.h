//
//  UIFocusGuide.h
//  UIKit
//
//  Copyright © 2015-2017 Apple Inc. All rights reserved.
//

#import <UIKit/UILayoutGuide.h>

@protocol UIFocusEnvironment;

NS_ASSUME_NONNULL_BEGIN

/// UIFocusGuides are UILayoutGuide subclasses that participate in the focus system from within their owning view. A UIFocusGuide may be used to expose non-view areas as focusable.
NS_CLASS_AVAILABLE_IOS(9_0) @interface UIFocusGuide : UILayoutGuide

/// If disabled, UIFocusGuides are ignored by the focus engine, but still participate in layout. Modifying this flag allows you to conditionally enable or disable certain focus behaviors. YES by default.
@property (nonatomic, getter=isEnabled) BOOL enabled;

/// Setting preferredFocusEnvironments to a non-empty array marks this guide's layoutFrame as focusable. If empty, this guide is effectively disabled.
/// If focused, the guide attempts to redirect focus to each environment in the array, in order, stopping when a focusable item in an environment has been found.
@property (nonatomic, copy, null_resettable) NSArray<id<UIFocusEnvironment>> *preferredFocusEnvironments NS_AVAILABLE_IOS(10_0);

/// Setting a preferred focused view marks this guide's layoutFrame as focusable, and if focused, redirects focus to its preferred focused view. If nil, this guide is effectively disabled.
@property (nonatomic, weak, nullable) UIView *preferredFocusedView NS_DEPRECATED_IOS(9_0, 10_0, "Use -preferredFocusEnvironments instead.");

@end

NS_ASSUME_NONNULL_END
