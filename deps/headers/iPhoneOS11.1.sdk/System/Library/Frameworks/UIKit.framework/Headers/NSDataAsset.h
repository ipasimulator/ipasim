//
//  NSDataAsset.h
//  UIKit
//
//  Copyright © 2015-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// NSDataAsset represents the contents of data entries in your asset catalog.
/// Data assets are not in the same class of stored content as images, so you cannot use a data asset to get image data for an image.
NS_CLASS_AVAILABLE_IOS(9_0) @interface NSDataAsset : NSObject<NSCopying>

- (instancetype)init NS_UNAVAILABLE;

/// Equivalent to -initWithName:name bundle:[NSBundle mainBundle];
- (nullable instancetype)initWithName:(NSString *)name;
/// Create a data asset with the given name from the given bundle. Returns nil if the asset was not found.
- (nullable instancetype)initWithName:(NSString *)name bundle:(NSBundle *)bundle NS_DESIGNATED_INITIALIZER;

/// The name used to reference the data asset
@property (nonatomic, readonly, copy) NSString *name;
/// The data for this asset, as stored in the asset catalog
@property (nonatomic, readonly, copy) NSData *data;
/// The Uniform Type Identifier for this data object.
@property (nonatomic, readonly, copy) NSString *typeIdentifier;

@end

NS_ASSUME_NONNULL_END
