//
//  UIToolbar.h
//  UIKit
//
//  Copyright (c) 2006-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>
#import <UIKit/UIView.h>
#import <UIKit/UIInterface.h>
#import <UIKit/UIApplication.h>
#import <UIKit/UIBarButtonItem.h>
#import <UIKit/UIBarCommon.h>

NS_ASSUME_NONNULL_BEGIN

@class UIBarButtonItem, UIColor;
@protocol UIToolbarDelegate;

NS_CLASS_AVAILABLE_IOS(2_0) __TVOS_PROHIBITED @interface UIToolbar : UIView <UIBarPositioning>

@property(nonatomic) UIBarStyle barStyle UI_APPEARANCE_SELECTOR __TVOS_PROHIBITED; // default is UIBarStyleDefault
@property(nullable, nonatomic, copy) NSArray<UIBarButtonItem *> *items; // get/set visible UIBarButtonItem. default is nil. changes not animated. shown in order

/*
 New behavior on iOS 7.
 Default is YES.
 You may force an opaque background by setting the property to NO.
 If the toolbar has a custom background image, the default is inferred
 from the alpha values of the image—YES if it has any pixel with alpha < 1.0
 If you send setTranslucent:YES to a bar with an opaque custom background image
 it will apply a system opacity less than 1.0 to the image.
 If you send setTranslucent:NO to a bar with a translucent custom background image
 it will provide an opaque background for the image using the bar's barTintColor if defined, or black
 for UIBarStyleBlack or white for UIBarStyleDefault if barTintColor is nil.
 */
@property(nonatomic,assign,getter=isTranslucent) BOOL translucent NS_AVAILABLE_IOS(3_0) UI_APPEARANCE_SELECTOR; // Default is NO on iOS 6 and earlier. Always YES if barStyle is set to UIBarStyleBlackTranslucent

- (void)setItems:(nullable NSArray<UIBarButtonItem *> *)items animated:(BOOL)animated;   // will fade in or out or reorder and adjust spacing

/*
 The behavior of tintColor for bars has changed on iOS 7.0. It no longer affects the bar's background
 and behaves as described for the tintColor property added to UIView.
 To tint the bar's background, please use -barTintColor.
 */
@property(null_resettable, nonatomic, strong) UIColor *tintColor;
@property(nullable, nonatomic, strong) UIColor *barTintColor NS_AVAILABLE_IOS(7_0) UI_APPEARANCE_SELECTOR;  // default is nil

/* Use these methods to set and access custom background images for toolbars.
      Default is nil. When non-nil the image will be used instead of the system image for toolbars in the
 specified position.
      For the barMetrics argument, UIBarMetricsDefault is the fallback.
 
 DISCUSSION: Interdependence of barStyle, tintColor, backgroundImage.
 When barStyle or tintColor is set as well as the bar's background image,
 the bar buttons (unless otherwise customized) will inherit the underlying
 barStyle or tintColor.
 */
- (void)setBackgroundImage:(nullable UIImage *)backgroundImage forToolbarPosition:(UIBarPosition)topOrBottom barMetrics:(UIBarMetrics)barMetrics NS_AVAILABLE_IOS(5_0) UI_APPEARANCE_SELECTOR;
- (nullable UIImage *)backgroundImageForToolbarPosition:(UIBarPosition)topOrBottom barMetrics:(UIBarMetrics)barMetrics NS_AVAILABLE_IOS(5_0) UI_APPEARANCE_SELECTOR;

/* Default is nil. When non-nil, a custom shadow image to show instead of the default shadow image. For a custom shadow to be shown, a custom background image must also be set with -setBackgroundImage:forToolbarPosition:barMetrics: (if the default background image is used, the default shadow image will be used).
 */
- (void)setShadowImage:(nullable UIImage *)shadowImage forToolbarPosition:(UIBarPosition)topOrBottom NS_AVAILABLE_IOS(6_0) UI_APPEARANCE_SELECTOR;
- (nullable UIImage *)shadowImageForToolbarPosition:(UIBarPosition)topOrBottom NS_AVAILABLE_IOS(6_0) UI_APPEARANCE_SELECTOR;

@property(nullable, nonatomic, weak) id<UIToolbarDelegate> delegate NS_AVAILABLE_IOS(7_0); // You may not set the delegate when the toolbar is managed by a UINavigationController.
@end

__TVOS_PROHIBITED
@protocol UIToolbarDelegate <UIBarPositioningDelegate>
@end

NS_ASSUME_NONNULL_END
