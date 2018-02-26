//
//  UISpringLoadedInteractionSupporting.h
//  UIKit
//
//  Copyright © 2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(tvos, watchos)
@protocol UISpringLoadedInteractionSupporting <NSObject>

@property (nonatomic, assign, getter=isSpringLoaded) BOOL springLoaded UIKIT_AVAILABLE_IOS_ONLY(11_0);

@end

NS_ASSUME_NONNULL_END
