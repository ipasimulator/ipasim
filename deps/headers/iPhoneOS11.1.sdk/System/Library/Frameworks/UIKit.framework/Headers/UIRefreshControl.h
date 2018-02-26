//
//  UIRefreshControl.h
//  UIKit
//
//  Copyright 2012-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIControl.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN
    
NS_CLASS_AVAILABLE_IOS(6_0) __TVOS_PROHIBITED @interface UIRefreshControl : UIControl

/* The designated initializer
 * This initializes a UIRefreshControl with a default height and width.
 * Once assigned to a UITableViewController, the frame of the control is managed automatically.
 * When a user has pulled-to-refresh, the UIRefreshControl fires its UIControlEventValueChanged event.
 *
*/
- (instancetype)init;

@property (nonatomic, readonly, getter=isRefreshing) BOOL refreshing;

@property (null_resettable, nonatomic, strong) UIColor *tintColor;
@property (nullable, nonatomic, strong) NSAttributedString *attributedTitle UI_APPEARANCE_SELECTOR;

// May be used to indicate to the refreshControl that an external event has initiated the refresh action
- (void)beginRefreshing NS_AVAILABLE_IOS(6_0);
// Must be explicitly called when the refreshing has completed
- (void)endRefreshing NS_AVAILABLE_IOS(6_0);

@end

NS_ASSUME_NONNULL_END
