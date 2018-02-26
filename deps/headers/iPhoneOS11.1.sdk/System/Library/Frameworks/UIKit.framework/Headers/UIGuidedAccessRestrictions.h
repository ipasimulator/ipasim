//
//  UIGuidedAccessRestrictions.h
//  UIKit
//
//  Copyright (c) 2012-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

/*
 UIGuidedAccessRestrictions
 
 Guided Access is a feature that restricts iOS to running only one app, while disabling the use of hardware buttons.
 
 This protocol allows an app to specify additional features that can be disabled by users when in Guided Access mode.
 
 For example, a Photos-based app could disallow photo deletion.
 If the user disabled photo deletion, guidedAccessRestrictionWithIdentifier:willChangeState: will be called.
 The app should then completely remove the ability to delete photos through any user interface mechanism.
 
 The app should provide the list of semantic features that are desirable to be disabled while running in Guided Access mode.
 */

typedef NS_ENUM(NSInteger, UIGuidedAccessRestrictionState) {
    UIGuidedAccessRestrictionStateAllow,
    UIGuidedAccessRestrictionStateDeny
};

/*
 UIGuidedAccessRestrictionDelegate
 
 Implement on the application delegate to present the user with additional Guided Access restrictions.
 
 The initial state of all Guided Access restrictions is UIGuidedAccessRestrictionStateAllow.
 */
NS_CLASS_AVAILABLE_IOS(7_0) @protocol UIGuidedAccessRestrictionDelegate <NSObject>

@required

/*
 Returns a list of restriction identifiers in the order they will be presented to the user.
 Each restriction identifier must be unique string.
 For example: com.MyCompany.MyApp.SomeRestrictionIdentifier
 */
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly, nullable) NSArray<NSString *> *guidedAccessRestrictionIdentifiers;
#else
- (nullable NSArray<NSString *> *)guidedAccessRestrictionIdentifiers;
#endif

// Called each time the restriction associated with the identifier changes state.
- (void)guidedAccessRestrictionWithIdentifier:(NSString *)restrictionIdentifier didChangeState:(UIGuidedAccessRestrictionState)newRestrictionState;

// Returns a localized string that describes the restriction associated with the identifier.
- (nullable NSString *)textForGuidedAccessRestrictionWithIdentifier:(NSString *)restrictionIdentifier;

@optional

// Returns a localized string that gives additional detail about the restriction associated with the identifier.
- (nullable NSString *)detailTextForGuidedAccessRestrictionWithIdentifier:(NSString *)restrictionIdentifier;

@end

// Returns the state of the restriction associated with the identifier.
UIKIT_EXTERN UIGuidedAccessRestrictionState UIGuidedAccessRestrictionStateForIdentifier(NSString *restrictionIdentifier) NS_AVAILABLE_IOS(7_0);

NS_ASSUME_NONNULL_END
