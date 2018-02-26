//
//  UIFocusSystem.h
//  UIKit
//
//  Copyright © 2016-2017 Apple Inc. All rights reserved.
//

#import <UIKit/UIFocus.h>

NS_ASSUME_NONNULL_BEGIN

/// UIFocusSystem instances manage focus state within a part of the user interface. They are in charge of tracking the current focused item, as well as processing focus updates.
NS_CLASS_AVAILABLE_IOS(11_0) @interface UIFocusSystem : NSObject

+ (instancetype)new NS_UNAVAILABLE;
- (instancetype)init NS_UNAVAILABLE;

/// Returns true if `environment` is an ancestor of `otherEnvironment`, or false if otherwise.
+ (BOOL)environment:(id<UIFocusEnvironment>)environment containsEnvironment:(id<UIFocusEnvironment>)otherEnvironment;

/// Registers a sound file for a given identifier.
+ (void)registerURL:(NSURL *)soundFileURL forSoundIdentifier:(UIFocusSoundIdentifier)identifier API_AVAILABLE(tvos(11.0)) API_UNAVAILABLE(ios, watchos);

@end

NS_ASSUME_NONNULL_END
