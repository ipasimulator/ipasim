//
//  WKInterfacePicker.h
//  WatchKit
//
//  Copyright (c) 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>
#import <WatchKit/WKInterfaceObject.h>
#import <WatchKit/WKInterfaceImage.h>

@class WKImage, WKPickerItem;

NS_ASSUME_NONNULL_BEGIN

// WKInterfacePicker is a UI component that presents items in a number of
// different styles for picking via the Digital Crown. These styles include:
//
// 1. List
// Items are shown in a vertically stacked list, similar to the UI shown during
// Activity Setup and Complication editing. Turning the Digital Crown moves up
// and down through the list.
//
// 2. Stack
// Items are shown as a stack of cards and can be flipped through via the crown.
//
// 3. Image Sequence
// Items are shown as a sequence of images, and turning the crown changes the
// visible image. Sequences of images can include animations, segments of a
// progress ring etc.
//
// Multiple pickers can be shown in a single Interface Controller, and they
// can be nested within a scrolling view.

WK_AVAILABLE_WATCHOS_ONLY(2.0)
@interface WKInterfacePicker : WKInterfaceObject

// Make the picker focused so Digital Crown input is directed to it. This is
// useful in cases where there are multiple on-screen pickers, or if the picker
// is nested in a scrollable view.
- (void)focus;

// Resigns focus from the picker. If the picker is nested in a scrollable
// view, the Digital Crown input will be used for scrolling.
- (void)resignFocus;

// Change the selected item index.
- (void)setSelectedItemIndex:(NSInteger)itemIndex;

// Configure the picker with a set of items, which will be displayed according
// to the style of the picker.
- (void)setItems:(nullable NSArray<WKPickerItem *> *)items;

// Configure the picker with one or more interface objects that support
// animated images. Turning the crown to adjust the picker will seek through the
// keyframes of any coordinated animations.
- (void)setCoordinatedAnimations:(nullable NSArray<WKInterfaceObject<WKImageAnimatable> *> *)coordinatedAnimations;

// Enable or disable the picker. When disabled, the picker cannot be focused.
- (void)setEnabled:(BOOL)enabled;

@end

WK_AVAILABLE_WATCHOS_ONLY(2.0)
@interface WKPickerItem : NSObject <NSSecureCoding>

// Text to show when the item is being displayed in a picker with the 'List' style.
@property (nonatomic, copy, nullable) NSString *title;

// Caption to show for the item when focus style includes a caption callout.
@property (nonatomic, copy, nullable) NSString *caption;

// An accessory image to show next to the title in a picker with the 'List'
// style. Note that the image will be scaled and centered to fit within
// an 13×13pt rect.
@property (nonatomic, copy, nullable) WKImage *accessoryImage;

// A custom image to show for the item, used instead of the title + accessory
// image when more flexibility is needed, or when displaying in the stack or
// sequence style. The image will be scaled and centered to fit within the
// picker's bounds or item row bounds.
@property (nonatomic, copy, nullable) WKImage *contentImage;

@end

NS_ASSUME_NONNULL_END
