//
//  UIImpactFeedbackGenerator.h
//  UIKit
//
//  Copyright © 2016-2017 Apple Inc. All rights reserved.
//

#import <UIKit/UIFeedbackGenerator.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, UIImpactFeedbackStyle) {
    UIImpactFeedbackStyleLight,
    UIImpactFeedbackStyleMedium,
    UIImpactFeedbackStyleHeavy
};

// UIImpactFeedbackGenerator is used to give user feedback when an impact between UI elements occurs
UIKIT_CLASS_AVAILABLE_IOS_ONLY(10_0) @interface UIImpactFeedbackGenerator : UIFeedbackGenerator

- (instancetype)initWithStyle:(UIImpactFeedbackStyle)style;

/// call when your UI element impacts something else
- (void)impactOccurred;

@end

NS_ASSUME_NONNULL_END
