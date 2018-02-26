//
//  NSIndexPath+UIKitAdditions.h
//  UIKit
//
//  Copyright (c) 2005-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// This category provides convenience methods to make it easier to use an NSIndexPath to represent a section and row/item, for use with UITableView and UICollectionView.
@interface NSIndexPath (UIKitAdditions)

+ (instancetype)indexPathForRow:(NSInteger)row inSection:(NSInteger)section;
+ (instancetype)indexPathForItem:(NSInteger)item inSection:(NSInteger)section NS_AVAILABLE_IOS(6_0);

// Returns the index at position 0.
@property (nonatomic, readonly) NSInteger section;

// Returns the index at position 1.
@property (nonatomic, readonly) NSInteger row;
// Returns the index at position 1 if it exists, otherwise returns NSNotFound.
@property (nonatomic, readonly) NSInteger item NS_AVAILABLE_IOS(6_0);

@end

NS_ASSUME_NONNULL_END
