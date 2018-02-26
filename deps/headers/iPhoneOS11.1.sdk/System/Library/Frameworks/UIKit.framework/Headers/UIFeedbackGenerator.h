//
//  UIFeedbackGenerator.h
//  UIKit
//
//  Copyright © 2016-2017 Apple Inc. All rights reserved.

#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

// UIFeedbackGenerator is an abstract class that should not be used directly
UIKIT_CLASS_AVAILABLE_IOS_ONLY(10_0) @interface UIFeedbackGenerator : NSObject

/// informs self that it will likely receive events soon, so that it can ensure minimal latency for any feedback generated
/// safe to call more than once before the generator receives an event, if events are still imminently possible
- (void)prepare;

@end

NS_ASSUME_NONNULL_END
