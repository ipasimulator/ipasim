//
//  WKGestureRecognizer.h
//  WatchKit
//
//  Copyright © 2015 Apple Inc. All rights reserved.
//


#import <WatchKit/WKDefines.h>


WK_AVAILABLE_WATCHOS_ONLY(3.0)
typedef NS_ENUM(NSInteger, WKGestureRecognizerState) {
    WKGestureRecognizerStatePossible,   // = UIGestureRecognizerStatePossible
    WKGestureRecognizerStateBegan,      // = UIGestureRecognizerStateBegan
    WKGestureRecognizerStateChanged,    // = UIGestureRecognizerStateChanged
    WKGestureRecognizerStateEnded,      // = UIGestureRecognizerStateEnded
    WKGestureRecognizerStateCancelled,  // = UIGestureRecognizerStateCancelled
    WKGestureRecognizerStateFailed,     // = UIGestureRecognizerStateFailed
    WKGestureRecognizerStateRecognized  // = UIGestureRecognizerStateRecognized
};

WK_AVAILABLE_WATCHOS_ONLY(3.0)
typedef NS_OPTIONS(NSUInteger, WKSwipeGestureRecognizerDirection) {
    WKSwipeGestureRecognizerDirectionRight = 1 << 0,    // = UISwipeGestureRecognizerDirectionRight
    WKSwipeGestureRecognizerDirectionLeft  = 1 << 1,    // = UISwipeGestureRecognizerDirectionLeft
    WKSwipeGestureRecognizerDirectionUp    = 1 << 2,    // = UISwipeGestureRecognizerDirectionUp
    WKSwipeGestureRecognizerDirectionDown  = 1 << 3     // = UISwipeGestureRecognizerDirectionDown
};


NS_ASSUME_NONNULL_BEGIN

WK_AVAILABLE_WATCHOS_ONLY(3.0)
@interface WKGestureRecognizer : NSObject   // abstract class

@property(nonatomic, readonly) WKGestureRecognizerState state;
@property(nonatomic, getter=isEnabled) BOOL enabled;

- (CGPoint)locationInObject;      // always refers to the interface object the gesture recognizer is attached to
- (CGRect)objectBounds;           // locationInObject's viewBounds

@end


WK_AVAILABLE_WATCHOS_ONLY(3.0)
@interface WKTapGestureRecognizer : WKGestureRecognizer

@property(nonatomic) NSUInteger numberOfTapsRequired;

@end


WK_AVAILABLE_WATCHOS_ONLY(3.0)
@interface WKLongPressGestureRecognizer : WKGestureRecognizer

@property(nonatomic) CFTimeInterval minimumPressDuration;
@property(nonatomic) NSUInteger numberOfTapsRequired;
@property(nonatomic) CGFloat allowableMovement;

@end


WK_AVAILABLE_WATCHOS_ONLY(3.0)
@interface WKSwipeGestureRecognizer : WKGestureRecognizer

@property(nonatomic) WKSwipeGestureRecognizerDirection direction;

@end


WK_AVAILABLE_WATCHOS_ONLY(3.0)
@interface WKPanGestureRecognizer : WKGestureRecognizer

- (CGPoint)translationInObject;   // always refers to the interface object the gesture recognizer is attached to
- (CGPoint)velocityInObject;      // always refers to the interface object the gesture recognizer is attached to

@end

NS_ASSUME_NONNULL_END
