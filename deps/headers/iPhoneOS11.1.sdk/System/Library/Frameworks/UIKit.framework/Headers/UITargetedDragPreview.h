//
//  UITargetedDragPreview.h
//  UIKit
//
//  Copyright © 2017 Apple Inc. All rights reserved.
//

#import <CoreGraphics/CoreGraphics.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class UIDragPreviewParameters, UIView;

UIKIT_EXTERN API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, tvos) @interface UIDragPreviewTarget : NSObject <NSCopying>

/* UIDragPreviewTarget specifies where a drag preview should come from, or go to.
 *
 * `container` must be a view that is currently in a window.
 * `center` specifies where the center of the drag preview should go,
 * in `container`'s coordinate system.
 * `transform` is an additional transform to apply to the drag preview,
 * for special effects like rotating or scaling the preview.
 * Use CGAffineTransformIdentity if you only want the preview to move.
 */
- (instancetype)initWithContainer:(UIView *)container center:(CGPoint)center transform:(CGAffineTransform)transform NS_DESIGNATED_INITIALIZER;

/* As above, but with transform = CGAffineTransformIdentity.
 */
- (instancetype)initWithContainer:(UIView *)container center:(CGPoint)center;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@property (nonatomic, readonly) UIView *container;
@property (nonatomic, readonly) CGPoint center;
@property (nonatomic, readonly) CGAffineTransform transform;

@end

UIKIT_EXTERN API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, tvos) @interface UITargetedDragPreview : NSObject <NSCopying>

/* UITargetedDragPreview is a preview used during a lift, drop, or cancel animation.
 *
 * The preview will show the view, including all subviews, live. 
 * The UITargetedDragPreview will not change or move the view.
 */

/* To use this initializer, the view need not be in a window.
 */
- (instancetype)initWithView:(UIView *)view parameters:(UIDragPreviewParameters *)parameters target:(UIDragPreviewTarget *)target NS_DESIGNATED_INITIALIZER;

/* To use this initializer, the view must be in a window.
 * Sets the target based on the view's current superview, center, and transform.
 */
- (instancetype)initWithView:(UIView *)view parameters:(UIDragPreviewParameters *)parameters;

/* To use this initializer, the view must be in a window.
 * Sets the parameters to defaults.
 * Sets the target based on the view's current superview, center, and transform.
 */
- (instancetype)initWithView:(UIView *)view;

- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;

@property (nonatomic, readonly) UIDragPreviewTarget* target;

@property (nonatomic, readonly) UIView *view;

@property (nonatomic, readonly, copy) UIDragPreviewParameters *parameters;

/* Provide the size of the item.
 * You might use this size to create an appropriately-sized gap in your view,
 * where this item will land when it is dropped.
 */
@property (nonatomic, readonly) CGSize size;

/* Returns a preview with the same view and parameters, but a new target.
 *
 * You might call this in a UIDropInteractionDelegate in
 * -dropInteraction:previewForDroppingItem:withDefault:, or in
 * a UIDropInteractionDelegate in -dropInteraction:previewForCancellingItem:withDefault:,
 * to direct the default UITargetedDragPreview to a different target.
 */
- (UITargetedDragPreview *)retargetedPreviewWithTarget:(UIDragPreviewTarget *)newTarget;

@end

NS_ASSUME_NONNULL_END
