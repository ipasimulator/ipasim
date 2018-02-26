//
//  UINavigationItem.h
//  UIKit
//
//  Copyright © 2016-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIView.h>
#import <UIKit/UIBarButtonItem.h>

@class UISearchController;

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, UINavigationItemLargeTitleDisplayMode) {
    /// Automatically use the large out-of-line title based on the state of the previous item in the navigation bar. An item with largeTitleDisplayMode=Automatic will show or hide the large title based on the request of the previous navigation item. If the first item pushed is set to Automatic, then it will show the large title if the navigation bar has prefersLargeTitles=YES.
    UINavigationItemLargeTitleDisplayModeAutomatic,
    /// Always use a larger title when this item is top most.
    UINavigationItemLargeTitleDisplayModeAlways,
    /// Never use a larger title when this item is top most.
    UINavigationItemLargeTitleDisplayModeNever,
} NS_SWIFT_NAME(UINavigationItem.LargeTitleDisplayMode);

NS_CLASS_AVAILABLE_IOS(2_0) @interface UINavigationItem : NSObject <NSCoding>

- (instancetype)initWithTitle:(NSString *)title NS_DESIGNATED_INITIALIZER;
- (nullable instancetype)initWithCoder:(NSCoder *)coder NS_DESIGNATED_INITIALIZER;

@property(nullable, nonatomic,copy)   NSString        *title;             // Title when topmost on the stack. default is nil
@property(nullable, nonatomic,strong) UIView          *titleView;         // Custom view to use in lieu of a title. May be sized horizontally. Only used when item is topmost on the stack.

@property(nullable,nonatomic,copy)   NSString *prompt __TVOS_PROHIBITED;     // Explanatory text to display above the navigation bar buttons.
@property(nullable,nonatomic,strong) UIBarButtonItem *backBarButtonItem __TVOS_PROHIBITED; // Bar button item to use for the back button in the child navigation item.

@property(nonatomic,assign) BOOL hidesBackButton __TVOS_PROHIBITED; // If YES, this navigation item will hide the back button when it's on top of the stack.
- (void)setHidesBackButton:(BOOL)hidesBackButton animated:(BOOL)animated __TVOS_PROHIBITED;

/* Use these properties to set multiple items in a navigation bar.
 The older single properties (leftBarButtonItem and rightBarButtonItem) now refer to
 the first item in the respective array of items.
 
 NOTE: You'll achieve the best results if you use either the singular properties or
 the plural properties consistently and don't try to mix them.
 
 leftBarButtonItems are placed in the navigation bar left to right with the first
 item in the list at the left outside edge and left aligned.
 rightBarButtonItems are placed right to left with the first item in the list at
 the right outside edge and right aligned.
 */
@property(nullable,nonatomic,copy) NSArray<UIBarButtonItem *> *leftBarButtonItems NS_AVAILABLE_IOS(5_0);
@property(nullable,nonatomic,copy) NSArray<UIBarButtonItem *> *rightBarButtonItems NS_AVAILABLE_IOS(5_0);
- (void)setLeftBarButtonItems:(nullable NSArray<UIBarButtonItem *> *)items animated:(BOOL)animated NS_AVAILABLE_IOS(5_0);
- (void)setRightBarButtonItems:(nullable NSArray<UIBarButtonItem *> *)items animated:(BOOL)animated NS_AVAILABLE_IOS(5_0);

/* By default, the leftItemsSupplementBackButton property is NO. In this case,
 the back button is not drawn and the left item or items replace it. If you
 would like the left items to appear in addition to the back button (as opposed to instead of it)
 set leftItemsSupplementBackButton to YES.
 */
@property(nonatomic) BOOL leftItemsSupplementBackButton NS_AVAILABLE_IOS(5_0) __TVOS_PROHIBITED;

// Some navigation items want to display a custom left or right item when they're on top of the stack.
// A custom left item replaces the regular back button unless you set leftItemsSupplementBackButton to YES
@property(nullable, nonatomic,strong) UIBarButtonItem *leftBarButtonItem;
@property(nullable, nonatomic,strong) UIBarButtonItem *rightBarButtonItem;
- (void)setLeftBarButtonItem:(nullable UIBarButtonItem *)item animated:(BOOL)animated;
- (void)setRightBarButtonItem:(nullable UIBarButtonItem *)item animated:(BOOL)animated;

/// When UINavigationBar.prefersLargeTitles=YES, this property controls when the larger out-of-line title is displayed. If prefersLargeTitles=NO, this property has no effect. The default value is Automatic.
@property (nonatomic, readwrite, assign) UINavigationItemLargeTitleDisplayMode largeTitleDisplayMode API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(tvos);

// A view controller that will be shown inside of a navigation controller can assign a UISearchController to this property to display the search controller’s search bar in its containing navigation controller’s navigation bar.
@property (nonatomic, retain, nullable) UISearchController *searchController API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(tvos);

// If this property is true (the default), the searchController’s search bar will hide as the user scrolls in the top view controller’s scroll view. If false, the search bar will remain visible and pinned underneath the navigation bar.
@property (nonatomic) BOOL hidesSearchBarWhenScrolling API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(tvos);


@end

NS_ASSUME_NONNULL_END
