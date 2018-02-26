//
//  UIReferenceLibraryViewController.h
//  UIKit
//
//  Copyright 2011-2017 Apple Inc. All rights reserved.
//

#import <UIKit/UIViewController.h>

NS_ASSUME_NONNULL_BEGIN

NS_CLASS_AVAILABLE_IOS(5_0) __TVOS_PROHIBITED
@interface UIReferenceLibraryViewController : UIViewController {}

/*! Returns YES if any installed dictionary has a definition for the provided term.
 */
+ (BOOL)dictionaryHasDefinitionForTerm:(NSString *)term;

/*! Initializes an instance of a UIReferenceLibraryViewController with the term provided.
 */
- (instancetype)initWithTerm:(NSString *)term NS_DESIGNATED_INITIALIZER;
- (instancetype) initWithCoder:(nonnull NSCoder *)aDecoder NS_DESIGNATED_INITIALIZER; // Declared solely for the sake of potential subclassers.

- (instancetype)initWithNibName:(nullable NSString *)nibNameOrNil bundle:(nullable NSBundle *)nibBundleOrNil NS_UNAVAILABLE;
- (instancetype)init NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
