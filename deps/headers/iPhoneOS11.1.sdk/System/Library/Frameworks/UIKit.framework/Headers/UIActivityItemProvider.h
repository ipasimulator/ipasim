//
//  UIActivityItemProvider.h
//  UIKit
//
//  Copyright 2012-2017 Apple Inc. All rights reserved.
//
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UIKit/UIKitDefines.h>
#import <UIKit/UIActivity.h>

NS_ASSUME_NONNULL_BEGIN

@class UIActivityViewController, UIImage;

@protocol UIActivityItemSource <NSObject>

@required

- (id)activityViewControllerPlaceholderItem:(UIActivityViewController *)activityViewController;	// called to determine data type. only the class of the return type is consulted. it should match what -itemForActivityType: returns later
- (nullable id)activityViewController:(UIActivityViewController *)activityViewController itemForActivityType:(nullable UIActivityType)activityType;	// called to fetch data after an activity is selected. you can return nil.

@optional

- (NSString *)activityViewController:(UIActivityViewController *)activityViewController subjectForActivityType:(nullable UIActivityType)activityType; // if activity supports a Subject field. iOS 7.0
- (NSString *)activityViewController:(UIActivityViewController *)activityViewController dataTypeIdentifierForActivityType:(nullable UIActivityType)activityType; // UTI for item if it is an NSData. iOS 7.0. will be called with nil activity and then selected activity
- (nullable UIImage *)activityViewController:(UIActivityViewController *)activityViewController thumbnailImageForActivityType:(nullable UIActivityType)activityType suggestedSize:(CGSize)size; // if activity supports preview image. iOS 7.0

@end

NS_CLASS_AVAILABLE_IOS(6_0) __TVOS_PROHIBITED @interface UIActivityItemProvider : NSOperation <UIActivityItemSource>

- (instancetype)init NS_UNAVAILABLE;
- (instancetype)initWithPlaceholderItem:(id)placeholderItem NS_DESIGNATED_INITIALIZER;               // placeHolder is the return value for -activityViewControllerPlaceholderItem:

@property(nullable,nonatomic,strong,readonly) id        placeholderItem;
@property(nullable,nonatomic,copy,readonly)   UIActivityType activityType;     // activity type available when -item is called. nil at other times. use this in your -item method to customize the data to return

#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonnull, nonatomic, readonly) id item;   // called on secondary thread when user selects an activity. you must subclass and return a non-nil value. The item can use the UIActivityItemSource protocol to return extra information
#else
- (nonnull id)item;   // called on secondary thread when user selects an activity. you must subclass and return a non-nil value. The item can use the UIActivityItemSource protocol to return extra information
#endif

@end

NS_ASSUME_NONNULL_END
