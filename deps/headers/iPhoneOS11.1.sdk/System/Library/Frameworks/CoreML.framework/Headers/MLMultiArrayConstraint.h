//
//  MLMultiArrayConstraint.h
//  CoreML
//
//  Copyright © 2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreML/MLMultiArray.h>

NS_ASSUME_NONNULL_BEGIN

/*!
 * Constraint describing expected MLMultiArray properties
 */
API_AVAILABLE(macos(10.13), ios(11.0), watchos(4.0), tvos(11.0))
@interface MLMultiArrayConstraint : NSObject

/// Required shape of array
@property (readonly, nonatomic) NSArray<NSNumber *> *shape;

/// Required dataType
@property (readonly, nonatomic) MLMultiArrayDataType dataType;

@end

NS_ASSUME_NONNULL_END

