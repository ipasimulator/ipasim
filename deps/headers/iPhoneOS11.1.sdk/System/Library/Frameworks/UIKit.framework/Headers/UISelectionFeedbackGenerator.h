//
//  UISelectionFeedbackGenerator.h
//  UIKit
//
//  Copyright © 2016-2017 Apple Inc. All rights reserved.
//

#import <UIKit/UIFeedbackGenerator.h>

NS_ASSUME_NONNULL_BEGIN

// UISelectionFeedbackGenerator is used to give user feedback when a selection changes
UIKIT_CLASS_AVAILABLE_IOS_ONLY(10_0) @interface UISelectionFeedbackGenerator : UIFeedbackGenerator

/// call when the selection changes (not on initial selection)
- (void)selectionChanged;

@end

NS_ASSUME_NONNULL_END
