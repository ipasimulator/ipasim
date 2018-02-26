//
//  UIAccessibilityIdentification.h
//  UIKit
//
//  Copyright 2010-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIView.h>
#import <UIKit/UIImage.h>
#import <UIKit/UIBarItem.h>

NS_ASSUME_NONNULL_BEGIN

@protocol UIAccessibilityIdentification <NSObject>
@required

/*
 A string that identifies the user interface element.
 default == nil
*/
@property(nullable, nonatomic, copy) NSString *accessibilityIdentifier NS_AVAILABLE_IOS(5_0);

@end

@interface UIView (UIAccessibility) <UIAccessibilityIdentification>
@end

@interface UIBarItem (UIAccessibility) <UIAccessibilityIdentification>
@end

/*
 Defaults to the filename of the image, if available.
 The default identifier for a UIImageView will be the identifier of its UIImage.
 */
@interface UIImage (UIAccessibility) <UIAccessibilityIdentification>
@end

NS_ASSUME_NONNULL_END
