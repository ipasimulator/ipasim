/*
 *  CMLogItem.h
 *  CoreMotion
 *
 *  Copyright (c) 2010 Apple Inc. All rights reserved.
 *
 */

#import <Foundation/Foundation.h>

#import <CoreMotion/CMAvailability.h>

NS_ASSUME_NONNULL_BEGIN

NS_CLASS_AVAILABLE(NA,4_0)
@interface CMLogItem : NSObject <NSSecureCoding, NSCopying>
{
@private
	id _internalLogItem;
}

/*
 *  timestamp
 *  
 *  Discussion:
 *    Time at which the item is valid.
 *
 */
@property(readonly, nonatomic) NSTimeInterval timestamp;

@end

NS_ASSUME_NONNULL_END
