//
//  UISearchDisplayController.h
//  UIKit
//
//  Copyright (c) 2009-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIView.h>
#import <UIKit/UIKitDefines.h>
#import <UIKit/UILabel.h>
#import <UIKit/UITableView.h>
#import <UIKit/UINavigationBar.h>

NS_ASSUME_NONNULL_BEGIN

@class UISearchBar, UITableView, UIViewController, UIPopoverController;
@protocol UITableViewDataSource, UITableViewDelegate, UISearchDisplayDelegate;

NS_CLASS_DEPRECATED_IOS(3_0, 8_0, "UISearchDisplayController has been replaced with UISearchController") __TVOS_PROHIBITED
@interface UISearchDisplayController : NSObject

- (instancetype)initWithSearchBar:(UISearchBar *)searchBar contentsController:(UIViewController *)viewController;

@property(nullable,nonatomic,assign)                           id<UISearchDisplayDelegate> delegate;

@property(nonatomic,getter=isActive)  BOOL            active;  // configure the view controller for searching. default is NO. animated is NO
- (void)setActive:(BOOL)visible animated:(BOOL)animated;       // animate the view controller for searching

@property(nonatomic,readonly)                                  UISearchBar                *searchBar;
@property(nonatomic,readonly)                                  UIViewController           *searchContentsController; // the view we are searching (often a UITableViewController)
@property(nonatomic,readonly)                                  UITableView                *searchResultsTableView;   // will return non-nil. create if requested
@property(nullable,nonatomic,weak)                             id<UITableViewDataSource>  searchResultsDataSource;  // default is nil. delegate can provide
@property(nullable,nonatomic,weak)                             id<UITableViewDelegate>    searchResultsDelegate;    // default is nil. delegate can provide
@property(nullable,nonatomic,copy)                             NSString                   *searchResultsTitle NS_AVAILABLE_IOS(5_0); // default is nil. If nil, the controller uses the default title string

/* Displaying the search bar in a navigation bar will override the contentsController's navigationItem if it has one. */
@property (nonatomic, assign) BOOL displaysSearchBarInNavigationBar NS_AVAILABLE_IOS(7_0);
@property (nullable, nonatomic, readonly) UINavigationItem *navigationItem NS_AVAILABLE_IOS(7_0);

@end

__TVOS_PROHIBITED
@protocol UISearchDisplayDelegate <NSObject>

@optional

// when we start/end showing the search UI
- (void) searchDisplayControllerWillBeginSearch:(UISearchDisplayController *)controller NS_DEPRECATED_IOS(3_0,8_0);
- (void) searchDisplayControllerDidBeginSearch:(UISearchDisplayController *)controller NS_DEPRECATED_IOS(3_0,8_0);
- (void) searchDisplayControllerWillEndSearch:(UISearchDisplayController *)controller NS_DEPRECATED_IOS(3_0,8_0);
- (void) searchDisplayControllerDidEndSearch:(UISearchDisplayController *)controller NS_DEPRECATED_IOS(3_0,8_0);

// called when the table is created destroyed, shown or hidden. configure as necessary.
- (void)searchDisplayController:(UISearchDisplayController *)controller didLoadSearchResultsTableView:(UITableView *)tableView NS_DEPRECATED_IOS(3_0,8_0);
- (void)searchDisplayController:(UISearchDisplayController *)controller willUnloadSearchResultsTableView:(UITableView *)tableView NS_DEPRECATED_IOS(3_0,8_0);

// called when table is shown/hidden
- (void)searchDisplayController:(UISearchDisplayController *)controller willShowSearchResultsTableView:(UITableView *)tableView NS_DEPRECATED_IOS(3_0,8_0);
- (void)searchDisplayController:(UISearchDisplayController *)controller didShowSearchResultsTableView:(UITableView *)tableView NS_DEPRECATED_IOS(3_0,8_0);
- (void)searchDisplayController:(UISearchDisplayController *)controller willHideSearchResultsTableView:(UITableView *)tableView NS_DEPRECATED_IOS(3_0,8_0);
- (void)searchDisplayController:(UISearchDisplayController *)controller didHideSearchResultsTableView:(UITableView *)tableView NS_DEPRECATED_IOS(3_0,8_0);

// return YES to reload table. called when search string/option changes. convenience methods on top UISearchBar delegate methods
- (BOOL)searchDisplayController:(UISearchDisplayController *)controller shouldReloadTableForSearchString:(nullable NSString *)searchString NS_DEPRECATED_IOS(3_0,8_0);
- (BOOL)searchDisplayController:(UISearchDisplayController *)controller shouldReloadTableForSearchScope:(NSInteger)searchOption NS_DEPRECATED_IOS(3_0,8_0);

@end

NS_ASSUME_NONNULL_END
