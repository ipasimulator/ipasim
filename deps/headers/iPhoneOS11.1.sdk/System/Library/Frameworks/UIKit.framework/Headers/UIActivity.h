//
//  UIActivity.h
//  UIKit
//
//  Copyright 2012-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class UIImage, UIViewController;

#if UIKIT_STRING_ENUMS
typedef NSString * UIActivityType NS_EXTENSIBLE_STRING_ENUM;
#else
typedef NSString * UIActivityType;
#endif

UIKIT_EXTERN UIActivityType const UIActivityTypePostToFacebook     NS_AVAILABLE_IOS(6_0) __TVOS_PROHIBITED;
UIKIT_EXTERN UIActivityType const UIActivityTypePostToTwitter      NS_AVAILABLE_IOS(6_0) __TVOS_PROHIBITED;
UIKIT_EXTERN UIActivityType const UIActivityTypePostToWeibo        NS_AVAILABLE_IOS(6_0) __TVOS_PROHIBITED;    // SinaWeibo
UIKIT_EXTERN UIActivityType const UIActivityTypeMessage            NS_AVAILABLE_IOS(6_0) __TVOS_PROHIBITED;
UIKIT_EXTERN UIActivityType const UIActivityTypeMail               NS_AVAILABLE_IOS(6_0) __TVOS_PROHIBITED;
UIKIT_EXTERN UIActivityType const UIActivityTypePrint              NS_AVAILABLE_IOS(6_0) __TVOS_PROHIBITED;
UIKIT_EXTERN UIActivityType const UIActivityTypeCopyToPasteboard   NS_AVAILABLE_IOS(6_0) __TVOS_PROHIBITED;
UIKIT_EXTERN UIActivityType const UIActivityTypeAssignToContact    NS_AVAILABLE_IOS(6_0) __TVOS_PROHIBITED;
UIKIT_EXTERN UIActivityType const UIActivityTypeSaveToCameraRoll   NS_AVAILABLE_IOS(6_0) __TVOS_PROHIBITED;
UIKIT_EXTERN UIActivityType const UIActivityTypeAddToReadingList   NS_AVAILABLE_IOS(7_0) __TVOS_PROHIBITED;
UIKIT_EXTERN UIActivityType const UIActivityTypePostToFlickr       NS_AVAILABLE_IOS(7_0) __TVOS_PROHIBITED;
UIKIT_EXTERN UIActivityType const UIActivityTypePostToVimeo        NS_AVAILABLE_IOS(7_0) __TVOS_PROHIBITED;
UIKIT_EXTERN UIActivityType const UIActivityTypePostToTencentWeibo NS_AVAILABLE_IOS(7_0) __TVOS_PROHIBITED;
UIKIT_EXTERN UIActivityType const UIActivityTypeAirDrop            NS_AVAILABLE_IOS(7_0) __TVOS_PROHIBITED;
UIKIT_EXTERN UIActivityType const UIActivityTypeOpenInIBooks       NS_AVAILABLE_IOS(9_0) __TVOS_PROHIBITED;
UIKIT_EXTERN UIActivityType const UIActivityTypeMarkupAsPDF        NS_AVAILABLE_IOS(11_0) __TVOS_PROHIBITED;

typedef NS_ENUM(NSInteger, UIActivityCategory) {
    UIActivityCategoryAction,
    UIActivityCategoryShare,
} NS_ENUM_AVAILABLE_IOS(7_0) __TVOS_PROHIBITED;

NS_CLASS_AVAILABLE_IOS(6_0) __TVOS_PROHIBITED @interface UIActivity : NSObject

// override methods
#if UIKIT_DEFINE_AS_PROPERTIES
@property(class, nonatomic, readonly) UIActivityCategory activityCategory NS_AVAILABLE_IOS(7_0); // default is UIActivityCategoryAction.
#else
+ (UIActivityCategory)activityCategory NS_AVAILABLE_IOS(7_0); // default is UIActivityCategoryAction.
#endif

#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly, nullable) UIActivityType activityType;       // default returns nil. subclass may override to return custom activity type that is reported to completion handler
@property(nonatomic, readonly, nullable) NSString *activityTitle;      // default returns nil. subclass must override and must return non-nil value
@property(nonatomic, readonly, nullable) UIImage *activityImage;       // default returns nil. subclass must override and must return non-nil value
#else
- (nullable UIActivityType)activityType;       // default returns nil. subclass may override to return custom activity type that is reported to completion handler
- (nullable NSString *)activityTitle;      // default returns nil. subclass must override and must return non-nil value
- (nullable UIImage *)activityImage;       // default returns nil. subclass must override and must return non-nil value
#endif

- (BOOL)canPerformWithActivityItems:(NSArray *)activityItems;   // override this to return availability of activity based on items. default returns NO
- (void)prepareWithActivityItems:(NSArray *)activityItems;      // override to extract items and set up your HI. default does nothing

#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly, nullable) UIViewController *activityViewController;   // return non-nil to have view controller presented modally. call activityDidFinish at end. default returns nil
#else
- (nullable UIViewController *)activityViewController;   // return non-nil to have view controller presented modally. call activityDidFinish at end. default returns nil
#endif
- (void)performActivity;                        // if no view controller, this method is called. call activityDidFinish when done. default calls [self activityDidFinish:NO]

// state method

- (void)activityDidFinish:(BOOL)completed;   // activity must call this when activity is finished
@end

NS_ASSUME_NONNULL_END
