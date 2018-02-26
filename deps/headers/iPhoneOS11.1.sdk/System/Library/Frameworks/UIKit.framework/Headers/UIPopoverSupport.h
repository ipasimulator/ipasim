//
//  UIPopoverSupport.h
//  UIKit
//
//  Copyright (c) 2014-2017 Apple Inc. All rights reserved.
//

#import <UIKit/UIViewController.h>

typedef NS_OPTIONS(NSUInteger, UIPopoverArrowDirection) {
    UIPopoverArrowDirectionUp = 1UL << 0,
    UIPopoverArrowDirectionDown = 1UL << 1,
    UIPopoverArrowDirectionLeft = 1UL << 2,
    UIPopoverArrowDirectionRight = 1UL << 3,
    UIPopoverArrowDirectionAny = UIPopoverArrowDirectionUp | UIPopoverArrowDirectionDown | UIPopoverArrowDirectionLeft | UIPopoverArrowDirectionRight,
    UIPopoverArrowDirectionUnknown = NSUIntegerMax
};

@interface UIViewController (UIPopoverController)

/* modalInPopover is set on the view controller when you wish to force the popover hosting the view controller into modal behavior. When this is active, the popover will ignore events outside of its bounds until this is set to NO.
 */
@property (nonatomic,readwrite,getter=isModalInPopover) BOOL modalInPopover NS_AVAILABLE_IOS(3_2);

/* contentSizeForViewInPopover allows you to set the size of the content from within the view controller. This property is read/write, and you should generally not override it.
 */
@property (nonatomic,readwrite) CGSize contentSizeForViewInPopover NS_DEPRECATED_IOS(3_2, 7_0, "Use UIViewController.preferredContentSize instead.") __TVOS_PROHIBITED;

@end

