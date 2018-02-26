//
//  UIAttachmentBehavior.h
//  UIKit
//
//  Copyright (c) 2012-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIDynamicBehavior.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, UIAttachmentBehaviorType) {
    UIAttachmentBehaviorTypeItems,
    UIAttachmentBehaviorTypeAnchor
} NS_ENUM_AVAILABLE_IOS(7_0);

typedef struct {
    CGFloat minimum;
    CGFloat maximum;
} UIFloatRange;

UIKIT_EXTERN const UIFloatRange UIFloatRangeZero NS_AVAILABLE_IOS(9_0);
UIKIT_EXTERN const UIFloatRange UIFloatRangeInfinite NS_AVAILABLE_IOS(9_0);
UIKIT_EXTERN BOOL UIFloatRangeIsInfinite(UIFloatRange range) NS_AVAILABLE_IOS(9_0);
UIKIT_EXTERN BOOL UIFloatRangeIsEqualToRange(UIFloatRange range, UIFloatRange otherRange) NS_AVAILABLE_IOS(9_0);

UIKIT_STATIC_INLINE UIFloatRange UIFloatRangeMake(CGFloat minimum, CGFloat maximum) {
    return (UIFloatRange){minimum, maximum};
}

NS_CLASS_AVAILABLE_IOS(7_0) @interface UIAttachmentBehavior : UIDynamicBehavior

- (instancetype)initWithItem:(id <UIDynamicItem>)item attachedToAnchor:(CGPoint)point;
- (instancetype)initWithItem:(id <UIDynamicItem>)item offsetFromCenter:(UIOffset)offset attachedToAnchor:(CGPoint)point NS_DESIGNATED_INITIALIZER;

- (instancetype)initWithItem:(id <UIDynamicItem>)item1 attachedToItem:(id <UIDynamicItem>)item2;
- (instancetype)initWithItem:(id <UIDynamicItem>)item1 offsetFromCenter:(UIOffset)offset1 attachedToItem:(id <UIDynamicItem>)item2 offsetFromCenter:(UIOffset)offset2 NS_DESIGNATED_INITIALIZER;

/*!
 A sliding attachment allows for relative translation of two items along a specified axis with respect to the anchor point. A sliding
 attachment prevents all relative rotation of the dynamic items.
 @param item1 The first of two dynamic items connected by the attachment behavior.
 @param item2 The second of two dynamic items connected by the attachment behavior.
 @param point The point for which each item will be attached. The anchor point will be converted to each items local corrdinate system.
 @param axis Axis of allowed relative translation between local anchor point. Must be a unit vector.
 @see attachmentRange, Represents the slidable range of the attachment with respect to the anchor point along the specified axis, this range must include 0
 */
+ (instancetype)slidingAttachmentWithItem:(id <UIDynamicItem>)item1 attachedToItem:(id <UIDynamicItem>)item2 attachmentAnchor:(CGPoint)point axisOfTranslation:(CGVector)axis NS_AVAILABLE_IOS(9_0);

/*!
 A sliding attachment allows for translation of the item along a specified axis with respect to the anchor point. A sliding
 attachment prevents all relative rotation of the dynamic items.
 @param item1 The dynamic item connected by the attachment behavior.
 @param point The point for the item will be anchored by the attachment.
 @param axis Axis of allowed translation for the item. Must be a unit vector.
 @see attachmentRange, Represents the slidable range of the attachment with respect to the anchor point along the specified axis, this range must include 0
 */
+ (instancetype)slidingAttachmentWithItem:(id <UIDynamicItem>)item attachmentAnchor:(CGPoint)point axisOfTranslation:(CGVector)axis NS_AVAILABLE_IOS(9_0);

/*!
 A limit attachment imposes a maximum distance between two dynamic items, as if they were connected by a rope.
 @param item1 The first of two dynamic items connected by the attachment behavior.
 @param offset1 The point, within the dynamic item and described as an offset from its center point, for the attachment behavior.
 @param item2 The second of two dynamic items connected by the attachment behavior.
 @param offset2 The point, within the dynamic item and described as an offset from its center point, for the attachment behavior.
 @see length
 */
+ (instancetype)limitAttachmentWithItem:(id <UIDynamicItem>)item1 offsetFromCenter:(UIOffset)offset1 attachedToItem:(id <UIDynamicItem>)item2 offsetFromCenter:(UIOffset)offset2 NS_AVAILABLE_IOS(9_0);

/*!
 A fixed attachment fuses two dynamic items together at a reference point. 
 Fixed attachments are useful for creating complex shapes that can be broken apart later.
 @param item1 The first of two dynamic items connected by the attachment behavior.
 @param item2 The second of two dynamic items connected by the attachment behavior.
 @param point The point for which each item will be attached. The anchor point will be converted to each items local corrdinate system.
 */
+ (instancetype)fixedAttachmentWithItem:(id <UIDynamicItem>)item1 attachedToItem:(id <UIDynamicItem>)item2 attachmentAnchor:(CGPoint)point NS_AVAILABLE_IOS(9_0);

/*!
 A pin attachment allows two dynamic items to independently rotate around the anchor point as if pinned together. 
 You can configure how far the two objects may rotate and the resistance to rotation
 @param item1 The first of two dynamic items connected by the attachment behavior.
 @param item2 The second of two dynamic items connected by the attachment behavior.
 @param point The point for which each item will be attached. The anchor point will be converted to each items local corrdinate system
 @see frictionTorque, resistance to rotation
 */
+ (instancetype)pinAttachmentWithItem:(id <UIDynamicItem>)item1 attachedToItem:(id <UIDynamicItem>)item2 attachmentAnchor:(CGPoint)point NS_AVAILABLE_IOS(9_0);

@property (nonatomic, readonly, copy) NSArray<id <UIDynamicItem>> *items;

@property (readonly, nonatomic) UIAttachmentBehaviorType attachedBehaviorType;

@property (readwrite, nonatomic) CGPoint anchorPoint;

@property (readwrite, nonatomic) CGFloat length;
@property (readwrite, nonatomic) CGFloat damping; // 1: critical damping
@property (readwrite, nonatomic) CGFloat frequency; // in Hertz
@property (readwrite, nonatomic) CGFloat frictionTorque NS_AVAILABLE_IOS(9_0); // default is 0.0
@property (readwrite, nonatomic) UIFloatRange attachmentRange NS_AVAILABLE_IOS(9_0); // default is UIFloatRangeInfinite

@end

NS_ASSUME_NONNULL_END
