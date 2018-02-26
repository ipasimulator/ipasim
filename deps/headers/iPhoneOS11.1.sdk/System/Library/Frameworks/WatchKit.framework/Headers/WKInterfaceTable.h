//
//  WKInterfaceTable.h
//  WatchKit
//
//  Copyright (c) 2014-2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>
#import <WatchKit/WKInterfaceObject.h>

NS_ASSUME_NONNULL_BEGIN

WK_CLASS_AVAILABLE_IOS(8_2)
@interface WKInterfaceTable : WKInterfaceObject

- (void)setRowTypes:(NSArray<NSString*> *)rowTypes;                                         // row names. size of array is number of rows
- (void)setNumberOfRows:(NSInteger)numberOfRows withRowType:(NSString *)rowType; // repeating row name

@property(nonatomic,readonly) NSInteger numberOfRows;
- (nullable id)rowControllerAtIndex:(NSInteger)index;

- (void)insertRowsAtIndexes:(NSIndexSet *)rows withRowType:(NSString *)rowType;
- (void)removeRowsAtIndexes:(NSIndexSet *)rows;

- (void)scrollToRowAtIndex:(NSInteger)index;

- (void)performSegueForRow:(NSInteger)row WK_AVAILABLE_WATCHOS_ONLY(3.0);

@end

NS_ASSUME_NONNULL_END
