/*	NSLayoutAnchor.h
	Copyright (c) 2015-2017, Apple Inc. All rights reserved.
*/

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

NS_ASSUME_NONNULL_BEGIN

@class NSLayoutConstraint;

/* An NSLayoutAnchor represents an edge or dimension of a layout item.  Its concrete 
 subclasses allow concise creation of constraints.  
    Instead of invoking 
 
 +[NSLayoutConstraint constraintWithItem:attribute:relatedBy:toItem:attribute:multiplier:constant:] 
 
 directly, you can instead do something like this:
 
 [myView.topAnchor constraintEqualToAnchor:otherView.topAnchor constant:10];
 
 The -constraint* methods are available in multiple flavors to support use of different
 relations and omission of unused options.
 */
NS_CLASS_AVAILABLE_IOS(9_0)
@interface NSLayoutAnchor<AnchorType> : NSObject

/* These methods return an inactive constraint of the form thisAnchor = otherAnchor.
 */
- (NSLayoutConstraint *)constraintEqualToAnchor:(NSLayoutAnchor<AnchorType> *)anchor;
- (NSLayoutConstraint *)constraintGreaterThanOrEqualToAnchor:(NSLayoutAnchor<AnchorType> *)anchor;
- (NSLayoutConstraint *)constraintLessThanOrEqualToAnchor:(NSLayoutAnchor<AnchorType> *)anchor;

/* These methods return an inactive constraint of the form thisAnchor = otherAnchor + constant.
 */
- (NSLayoutConstraint *)constraintEqualToAnchor:(NSLayoutAnchor<AnchorType> *)anchor constant:(CGFloat)c;
- (NSLayoutConstraint *)constraintGreaterThanOrEqualToAnchor:(NSLayoutAnchor<AnchorType> *)anchor constant:(CGFloat)c;
- (NSLayoutConstraint *)constraintLessThanOrEqualToAnchor:(NSLayoutAnchor<AnchorType> *)anchor constant:(CGFloat)c;
@end


/* Axis-specific subclasses for location anchors: top/bottom, leading/trailing, baseline, etc.
 */
@class NSLayoutXAxisAnchor, NSLayoutYAxisAnchor, NSLayoutDimension;
NS_CLASS_AVAILABLE_IOS(9_0)
@interface NSLayoutXAxisAnchor : NSLayoutAnchor<NSLayoutXAxisAnchor *>
// A composite anchor for creating constraints relating horizontal distances between locations.
- (NSLayoutDimension *)anchorWithOffsetToAnchor:(NSLayoutXAxisAnchor *)otherAnchor API_AVAILABLE(ios(10.0),tvos(10.0));

@end

@interface NSLayoutXAxisAnchor (UIViewDynamicSystemSpacingSupport)
/* Constraints of the form,
        receiver [= | ≥ | ≤] 'anchor' + 'multiplier' * system space, 
 where the value of the system space is determined from information available from the anchors.
    The constraint affects how far the receiver will be positioned trailing 'anchor', per the effective user interface layout direction.
 */
- (NSLayoutConstraint *)constraintEqualToSystemSpacingAfterAnchor:(NSLayoutXAxisAnchor *)anchor multiplier:(CGFloat)multiplier API_AVAILABLE(ios(11.0),tvos(11.0));
- (NSLayoutConstraint *)constraintGreaterThanOrEqualToSystemSpacingAfterAnchor:(NSLayoutXAxisAnchor *)anchor multiplier:(CGFloat)multiplier API_AVAILABLE(ios(11.0),tvos(11.0));
- (NSLayoutConstraint *)constraintLessThanOrEqualToSystemSpacingAfterAnchor:(NSLayoutXAxisAnchor *)anchor multiplier:(CGFloat)multiplier API_AVAILABLE(ios(11.0),tvos(11.0));

@end
NS_CLASS_AVAILABLE_IOS(9_0)
@interface NSLayoutYAxisAnchor : NSLayoutAnchor<NSLayoutYAxisAnchor *>
// A composite anchor for creating constraints relating vertical distances between locations.
- (NSLayoutDimension *)anchorWithOffsetToAnchor:(NSLayoutYAxisAnchor *)otherAnchor API_AVAILABLE(ios(10.0),tvos(10.0));

@end

@interface NSLayoutYAxisAnchor (UIViewDynamicSystemSpacingSupport)
/* Constraints of the form,
        receiver [= | ≥ | ≤] 'anchor' + 'multiplier' * system space, 
 where the value of the system space is determined from information available from the anchors.
    The constraint affects how far the receiver will be positioned below 'anchor'. 
    If either the receiver or 'anchor' is the firstBaselineAnchor or lastBaselineAnchor of a view with text content
 then the spacing will depend on the fonts involved and will change when those do.
 */
- (NSLayoutConstraint *)constraintEqualToSystemSpacingBelowAnchor:(NSLayoutYAxisAnchor *)anchor multiplier:(CGFloat)multiplier API_AVAILABLE(ios(11.0),tvos(11.0));
- (NSLayoutConstraint *)constraintGreaterThanOrEqualToSystemSpacingBelowAnchor:(NSLayoutYAxisAnchor *)anchor multiplier:(CGFloat)multiplier API_AVAILABLE(ios(11.0),tvos(11.0));
- (NSLayoutConstraint *)constraintLessThanOrEqualToSystemSpacingBelowAnchor:(NSLayoutYAxisAnchor *)anchor multiplier:(CGFloat)multiplier API_AVAILABLE(ios(11.0),tvos(11.0));
@end


/* This layout anchor subclass is used for sizes (width & height).
 */
NS_CLASS_AVAILABLE_IOS(9_0)
@interface NSLayoutDimension : NSLayoutAnchor<NSLayoutDimension *>

/* These methods return an inactive constraint of the form 
    thisVariable = constant.
*/
- (NSLayoutConstraint *)constraintEqualToConstant:(CGFloat)c;
- (NSLayoutConstraint *)constraintGreaterThanOrEqualToConstant:(CGFloat)c;
- (NSLayoutConstraint *)constraintLessThanOrEqualToConstant:(CGFloat)c;

/* These methods return an inactive constraint of the form 
    thisAnchor = otherAnchor * multiplier.
*/
- (NSLayoutConstraint *)constraintEqualToAnchor:(NSLayoutDimension *)anchor multiplier:(CGFloat)m;
- (NSLayoutConstraint *)constraintGreaterThanOrEqualToAnchor:(NSLayoutDimension *)anchor multiplier:(CGFloat)m;
- (NSLayoutConstraint *)constraintLessThanOrEqualToAnchor:(NSLayoutDimension *)anchor multiplier:(CGFloat)m;

/* These methods return an inactive constraint of the form 
    thisAnchor = otherAnchor * multiplier + constant.
*/
- (NSLayoutConstraint *)constraintEqualToAnchor:(NSLayoutDimension *)anchor multiplier:(CGFloat)m constant:(CGFloat)c;
- (NSLayoutConstraint *)constraintGreaterThanOrEqualToAnchor:(NSLayoutDimension *)anchor multiplier:(CGFloat)m constant:(CGFloat)c;
- (NSLayoutConstraint *)constraintLessThanOrEqualToAnchor:(NSLayoutDimension *)anchor multiplier:(CGFloat)m constant:(CGFloat)c;
@end
NS_ASSUME_NONNULL_END
