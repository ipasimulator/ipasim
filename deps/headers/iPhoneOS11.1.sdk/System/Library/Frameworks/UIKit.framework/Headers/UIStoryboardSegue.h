//
//  UIStoryboardSegue.h
//  UIKit
//
//  Copyright 2011-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class UIViewController;

NS_CLASS_AVAILABLE_IOS(5_0) @interface UIStoryboardSegue : NSObject

// Convenience constructor for returning a segue that performs a handler block in its -perform method.
+ (instancetype)segueWithIdentifier:(nullable NSString *)identifier source:(UIViewController *)source destination:(UIViewController *)destination performHandler:(void (^)(void))performHandler NS_AVAILABLE_IOS(6_0);

- (instancetype)initWithIdentifier:(nullable NSString *)identifier source:(UIViewController *)source destination:(UIViewController *)destination NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

@property (nullable, nonatomic, copy, readonly) NSString *identifier;
@property (nonatomic, readonly) __kindof UIViewController *sourceViewController;
@property (nonatomic, readonly) __kindof UIViewController *destinationViewController;

/// Subclasses can override this method to augment or replace the effect of this segue. For example, to animate alongside the effect of a Modal Presentation segue, an override of this method can call super, then send -animateAlongsideTransition:completion: to the transitionCoordinator of the destinationViewController.
/// The segue runtime will call +[UIView setAnimationsAreEnabled:] prior to invoking this method, based on the value of the Animates checkbox in the Properties Inspector for the segue.
- (void)perform;

@end

/// Encapsulates the source of a prospective unwind segue.
/// You do not create instances of this class directly. Instead, UIKit creates an instance of this class and sends -allowedChildViewControllersForUnwindingFromSource: to each ancestor of the sourceViewController until it finds a view controller which returns YES from -canPerformUnwindSegueAction:fromViewController:withSender:.
NS_CLASS_AVAILABLE_IOS(9_0) @interface UIStoryboardUnwindSegueSource : NSObject

- (instancetype)init NS_UNAVAILABLE;

@property (readonly) UIViewController *sourceViewController;
@property (readonly) SEL unwindAction;
@property (readonly, nullable) id sender;

@end

NS_ASSUME_NONNULL_END
