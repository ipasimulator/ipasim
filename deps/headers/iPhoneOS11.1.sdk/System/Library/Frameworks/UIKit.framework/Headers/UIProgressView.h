//
//  UIProgressView.h
//  UIKit
//
//  Copyright (c) 2005-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIView.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class UIImageView, CAGradientLayer;

typedef NS_ENUM(NSInteger, UIProgressViewStyle) {
    UIProgressViewStyleDefault,     // normal progress bar
    UIProgressViewStyleBar __TVOS_PROHIBITED,     // for use in a toolbar
};

NS_CLASS_AVAILABLE_IOS(2_0) @interface UIProgressView : UIView <NSCoding>

- (instancetype)initWithFrame:(CGRect)frame NS_DESIGNATED_INITIALIZER;
- (nullable instancetype)initWithCoder:(NSCoder *)aDecoder NS_DESIGNATED_INITIALIZER;
- (instancetype)initWithProgressViewStyle:(UIProgressViewStyle)style; // sets the view height according to the style

@property(nonatomic) UIProgressViewStyle progressViewStyle; // default is UIProgressViewStyleDefault
@property(nonatomic) float progress;                        // 0.0 .. 1.0, default is 0.0. values outside are pinned.
@property(nonatomic, strong, nullable) UIColor* progressTintColor  NS_AVAILABLE_IOS(5_0) UI_APPEARANCE_SELECTOR;
@property(nonatomic, strong, nullable) UIColor* trackTintColor     NS_AVAILABLE_IOS(5_0) UI_APPEARANCE_SELECTOR;
@property(nonatomic, strong, nullable) UIImage* progressImage      NS_AVAILABLE_IOS(5_0) UI_APPEARANCE_SELECTOR;
@property(nonatomic, strong, nullable) UIImage* trackImage         NS_AVAILABLE_IOS(5_0) UI_APPEARANCE_SELECTOR;

- (void)setProgress:(float)progress animated:(BOOL)animated NS_AVAILABLE_IOS(5_0);

@property(nonatomic, strong, nullable) NSProgress *observedProgress NS_AVAILABLE_IOS(9_0);

@end

NS_ASSUME_NONNULL_END
