//
//  UIActivityIndicatorView.h
//  UIKit
//
//  Copyright (c) 2005-2017 Apple Inc. All rights reserved.
//

#import <UIKit/UIView.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, UIActivityIndicatorViewStyle) {
    UIActivityIndicatorViewStyleWhiteLarge,
    UIActivityIndicatorViewStyleWhite,
    UIActivityIndicatorViewStyleGray __TVOS_PROHIBITED,
};

NS_CLASS_AVAILABLE_IOS(2_0) @interface UIActivityIndicatorView : UIView <NSCoding>

- (instancetype)initWithActivityIndicatorStyle:(UIActivityIndicatorViewStyle)style NS_DESIGNATED_INITIALIZER; // sizes the view according to the style
- (instancetype)initWithFrame:(CGRect)frame NS_DESIGNATED_INITIALIZER;
- (instancetype) initWithCoder:(NSCoder *)coder NS_DESIGNATED_INITIALIZER;
   
@property(nonatomic) UIActivityIndicatorViewStyle activityIndicatorViewStyle; // default is UIActivityIndicatorViewStyleWhite
@property(nonatomic) BOOL                         hidesWhenStopped;           // default is YES. calls -setHidden when animating gets set to NO

@property (nullable, readwrite, nonatomic, strong) UIColor *color NS_AVAILABLE_IOS(5_0) UI_APPEARANCE_SELECTOR;

- (void)startAnimating;
- (void)stopAnimating;
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly, getter=isAnimating) BOOL animating;
#else
- (BOOL)isAnimating;
#endif

@end

NS_ASSUME_NONNULL_END
