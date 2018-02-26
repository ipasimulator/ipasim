//
//  UISearchController.h
//  UIKit
//
//  Copyright (c) 2014-2017 Apple Inc. All rights reserved.
//

#import <UIKit/UIPresentationController.h>
#import <UIKit/UIViewControllerTransitioning.h>
#import <UIKit/UISearchBar.h>

NS_ASSUME_NONNULL_BEGIN

@class UISearchController;

@protocol UISearchControllerDelegate <NSObject>
@optional
// These methods are called when automatic presentation or dismissal occurs. They will not be called if you present or dismiss the search controller yourself.
- (void)willPresentSearchController:(UISearchController *)searchController;
- (void)didPresentSearchController:(UISearchController *)searchController;
- (void)willDismissSearchController:(UISearchController *)searchController;
- (void)didDismissSearchController:(UISearchController *)searchController;

// Called after the search controller's search bar has agreed to begin editing or when 'active' is set to YES. If you choose not to present the controller yourself or do not implement this method, a default presentation is performed on your behalf.
- (void)presentSearchController:(UISearchController *)searchController;
@end

@protocol UISearchResultsUpdating <NSObject>
@required
// Called when the search bar's text or scope has changed or when the search bar becomes first responder.
- (void)updateSearchResultsForSearchController:(UISearchController *)searchController;
@end

NS_CLASS_AVAILABLE_IOS(8_0) @interface UISearchController : UIViewController <UIViewControllerTransitioningDelegate, UIViewControllerAnimatedTransitioning>

// Pass nil if you wish to display search results in the same view that you are searching. This is not supported on tvOS; please provide a results controller on tvOS.
- (instancetype)initWithSearchResultsController:(nullable UIViewController *)searchResultsController;

// The object responsible for updating the content of the searchResultsController.
@property (nullable, nonatomic, weak) id <UISearchResultsUpdating> searchResultsUpdater;

// Setting this property to YES is a convenience method that performs a default presentation of the search controller appropriate for how the controller is configured. Implement -presentSearchController: if the default presentation is not adequate.
@property (nonatomic, assign, getter = isActive) BOOL active;

@property (nullable, nonatomic, weak) id <UISearchControllerDelegate> delegate;
@property (nonatomic, assign) BOOL dimsBackgroundDuringPresentation __TVOS_PROHIBITED; // default is YES, and has the same behavior as obscuresBackgroundDuringPresentation.
@property (nonatomic, assign) BOOL obscuresBackgroundDuringPresentation NS_AVAILABLE_IOS(9_1); // default is YES. On tvOS, defaults to NO when contained in UISearchContainerViewController.
@property (nonatomic, assign) BOOL hidesNavigationBarDuringPresentation;     // default is YES

@property (nullable, nonatomic, strong, readonly) UIViewController *searchResultsController;

// You are free to become the search bar's delegate to monitor for text changes and button presses.
@property (nonatomic, strong, readonly) UISearchBar *searchBar;
@end

NS_ASSUME_NONNULL_END
