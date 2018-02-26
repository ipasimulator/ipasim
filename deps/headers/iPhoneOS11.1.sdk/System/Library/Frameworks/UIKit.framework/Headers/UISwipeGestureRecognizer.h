//
//  UISwipeGestureRecognizer.h
//  UIKit
//
//  Copyright (c) 2009-2017 Apple Inc. All rights reserved.
//

#import <CoreGraphics/CoreGraphics.h>
#import <UIKit/UIGestureRecognizer.h>

NS_ASSUME_NONNULL_BEGIN
    
// Recognizes: when numberOfTouchesRequired have moved mostly in the specified direction, enough to be considered a swipe.
//             a slow swipe requires high directional precision but a small distance
//             a fast swipe requires low directional precision but a large distance

// Touch Location Behaviors:
//     locationInView:         location where the swipe began. this is the centroid if more than one touch was involved
//     locationOfTouch:inView: location of a particular touch when the swipe began

typedef NS_OPTIONS(NSUInteger, UISwipeGestureRecognizerDirection) {
    UISwipeGestureRecognizerDirectionRight = 1 << 0,
    UISwipeGestureRecognizerDirectionLeft  = 1 << 1,
    UISwipeGestureRecognizerDirectionUp    = 1 << 2,
    UISwipeGestureRecognizerDirectionDown  = 1 << 3
};

NS_CLASS_AVAILABLE_IOS(3_2) @interface UISwipeGestureRecognizer : UIGestureRecognizer 

@property(nonatomic) NSUInteger                        numberOfTouchesRequired __TVOS_PROHIBITED; // default is 1. the number of fingers that must swipe
@property(nonatomic) UISwipeGestureRecognizerDirection direction;               // default is UISwipeGestureRecognizerDirectionRight. the desired direction of the swipe. multiple directions may be specified if they will result in the same behavior (for example, UITableView swipe delete)

@end

NS_ASSUME_NONNULL_END
