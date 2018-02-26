//
//  UIViewControllerTransitionCoordinator.h
//  UIKit
//
//  Copyright (c) 2013-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIViewController.h>

// An object that conforms to this protocol provides descriptive information about an active
// view controller transition.
NS_ASSUME_NONNULL_BEGIN

#if UIKIT_STRING_ENUMS
typedef NSString * UITransitionContextViewControllerKey NS_EXTENSIBLE_STRING_ENUM;
typedef NSString * UITransitionContextViewKey NS_EXTENSIBLE_STRING_ENUM;
#else
typedef NSString * UITransitionContextViewControllerKey;
typedef NSString * UITransitionContextViewKey;
#endif

@protocol UIViewControllerTransitionCoordinatorContext <NSObject>

// Most of the time isAnimated will be YES. For custom transitions that use the
// new UIModalPresentationCustom presentation type we invoke the
// animateTransition: even though the transition is not animated. (This allows
// the custom transition to add or remove subviews to the container view.)
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly, getter=isAnimated) BOOL animated;
#else
- (BOOL)isAnimated;
#endif

// A modal presentation style whose transition is being customized or UIModaPresentationNone if this is not a modal presentation
// or dismissal.
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly) UIModalPresentationStyle presentationStyle;
#else
- (UIModalPresentationStyle)presentationStyle;
#endif

/// initiallyInteractive indicates whether the transition was initiated as an interactive transition.
/// It never changes during the course of a transition.
/// It can only be YES if isAnimated is YES.
///If it is NO, then isInteractive can only be YES if isInterruptible is YES
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly) BOOL initiallyInteractive;
#else
- (BOOL)initiallyInteractive;
#endif
@property(nonatomic,readonly) BOOL isInterruptible NS_AVAILABLE_IOS(10_0);

// Interactive transitions have non-interactive segments. For example, they all complete non-interactively. Some interactive transitions may have
// intermediate segments that are not interactive.
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly, getter=isInteractive) BOOL interactive;
#else
- (BOOL)isInteractive;
#endif

// isCancelled is usually NO. It is only set to YES for an interactive transition that was cancelled.
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly, getter=isCancelled) BOOL cancelled;
#else
- (BOOL)isCancelled;
#endif

// The full expected duration of the transition if it is run non-interactively. 
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly) NSTimeInterval transitionDuration;
#else
- (NSTimeInterval)transitionDuration;
#endif

// These three methods are potentially meaningful for interactive transitions that are
// completing. It reports the percent complete of the transition when it moves
// to the non-interactive completion phase of the transition.
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly) CGFloat percentComplete;
@property(nonatomic, readonly) CGFloat completionVelocity;
@property(nonatomic, readonly) UIViewAnimationCurve completionCurve;
#else
- (CGFloat)percentComplete;
- (CGFloat)completionVelocity;
- (UIViewAnimationCurve)completionCurve;
#endif

// Currently only two keys are defined by the system:
//   UITransitionContextToViewControllerKey
//   UITransitionContextFromViewControllerKey
- (nullable __kindof UIViewController *)viewControllerForKey:(UITransitionContextViewControllerKey)key;

// Currently only two keys are defined by the system:
//   UITransitionContextToViewKey
//   UITransitionContextFromViewKey
- (nullable __kindof UIView *)viewForKey:(UITransitionContextViewKey)key NS_AVAILABLE_IOS(8_0);

// The view in which the animated transition is taking place.
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly) UIView *containerView;
#else
- (UIView *)containerView;
#endif

// This is either CGAffineTransformIdentity (indicating no rotation), or a rotation transform of +90, -90, or 180.
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly) CGAffineTransform targetTransform NS_AVAILABLE_IOS(8_0);
#else
- (CGAffineTransform)targetTransform NS_AVAILABLE_IOS(8_0);
#endif

@end

// An object conforming to this protocol is returned by -[UIViewController
// transitionCoordinator] when an active transition or presentation/dismissal is
// in flight. A container controller may not vend such an object. This is an
// ephemeral object that is released after the transition completes and the
// last callback has been made.

@protocol UIViewControllerTransitionCoordinator <UIViewControllerTransitionCoordinatorContext>


// Any animations specified will be run in the same animation context as the
// transition. If the animations are occurring in a view that is a not
// descendent of the containerView, then an ancestor view in which all of the
// animations are occuring should be specified.  The completionBlock is invoked
// after the transition completes. (Note that this may not be after all the
// animations specified by to call complete if the duration is not inherited.)
// It is perfectly legitimate to only specify a completion block. This method
// returns YES if the animations are successfully queued to run. The completions
// may be run even if the animations are not. Note that for transitioning
// animators that are not implemented with UIView animations, the alongside
// animations will be run just after their animateTransition: method returns.
//
- (BOOL)animateAlongsideTransition:(void (^ __nullable)(id <UIViewControllerTransitionCoordinatorContext>context))animation
                        completion:(void (^ __nullable)(id <UIViewControllerTransitionCoordinatorContext>context))completion;

// This alternative API is needed if the view is not a descendent of the container view AND you require this animation
// to be driven by a UIPercentDrivenInteractiveTransition interaction controller.
- (BOOL)animateAlongsideTransitionInView:(nullable UIView *)view
                               animation:(void (^ __nullable)(id <UIViewControllerTransitionCoordinatorContext>context))animation
                              completion:(void (^ __nullable)(id <UIViewControllerTransitionCoordinatorContext>context))completion;

// When a transition changes from interactive to non-interactive then handler is
// invoked. The handler will typically then do something depending on whether or
// not the transition isCancelled. Note that only interactive transitions can
// be cancelled and all interactive transitions complete as non-interactive
// ones. In general, when a transition is cancelled the view controller that was
// appearing will receive a viewWillDisappear: call, and the view controller
// that was disappearing will receive a viewWillAppear: call.  This handler is
// invoked BEFORE the "will" method calls are made.
- (void)notifyWhenInteractionEndsUsingBlock: (void (^)(id <UIViewControllerTransitionCoordinatorContext>context))handler NS_DEPRECATED_IOS(7_0, 10_0,"Use notifyWhenInteractionChangesUsingBlock");

// This method behavior is identical to the method above. On 10.0, however, the behavior has
// changed slightly to account for the fact that transitions can be interruptible. For interruptible transitions
// The block may be called multiple times. It is called each time the transition moves from an interactive to a 
// non-interactive state and vice-versa. The block is now also retained until the transition has completed.
- (void)notifyWhenInteractionChangesUsingBlock: (void (^)(id <UIViewControllerTransitionCoordinatorContext>context))handler NS_AVAILABLE_IOS(10_0);

@end

@interface UIViewController(UIViewControllerTransitionCoordinator)

// The default implementation will return a transition coordinator if called during
// an active presentation or dismissal. Otherwise it will ask the parent view
// controller. This method, if overridden, can first check if there is an
// appropriate transition coordinator to return, otherwise it should call
// super. Only custom container view controllers should ever need to override
// this method.
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly, nullable) id <UIViewControllerTransitionCoordinator> transitionCoordinator NS_AVAILABLE_IOS(7_0);
#else
- (nullable id <UIViewControllerTransitionCoordinator>)transitionCoordinator NS_AVAILABLE_IOS(7_0);
#endif
@end

NS_ASSUME_NONNULL_END
