//
//  NSLayoutConstraint.h
//  UIKit
//	
//  Copyright (c) 2009-2017 Apple Inc. All rights reserved.
//

#import <Foundation/NSObject.h>
#import <UIKit/UIGeometry.h>

NS_ASSUME_NONNULL_BEGIN

@class NSArray, NSDictionary, NSLayoutAnchor;


typedef NS_ENUM(NSInteger, NSLayoutRelation) {
    NSLayoutRelationLessThanOrEqual = -1,
    NSLayoutRelationEqual = 0,
    NSLayoutRelationGreaterThanOrEqual = 1,
};

typedef NS_ENUM(NSInteger, NSLayoutAttribute) {
    NSLayoutAttributeLeft = 1,
    NSLayoutAttributeRight,
    NSLayoutAttributeTop,
    NSLayoutAttributeBottom,
    NSLayoutAttributeLeading,
    NSLayoutAttributeTrailing,
    NSLayoutAttributeWidth,
    NSLayoutAttributeHeight,
    NSLayoutAttributeCenterX,
    NSLayoutAttributeCenterY,
    NSLayoutAttributeLastBaseline,
    NSLayoutAttributeBaseline NS_SWIFT_UNAVAILABLE("Use 'lastBaseline' instead") = NSLayoutAttributeLastBaseline,
    NSLayoutAttributeFirstBaseline NS_ENUM_AVAILABLE_IOS(8_0),
    
    
    NSLayoutAttributeLeftMargin NS_ENUM_AVAILABLE_IOS(8_0),
    NSLayoutAttributeRightMargin NS_ENUM_AVAILABLE_IOS(8_0),
    NSLayoutAttributeTopMargin NS_ENUM_AVAILABLE_IOS(8_0),
    NSLayoutAttributeBottomMargin NS_ENUM_AVAILABLE_IOS(8_0),
    NSLayoutAttributeLeadingMargin NS_ENUM_AVAILABLE_IOS(8_0),
    NSLayoutAttributeTrailingMargin NS_ENUM_AVAILABLE_IOS(8_0),
    NSLayoutAttributeCenterXWithinMargins NS_ENUM_AVAILABLE_IOS(8_0),
    NSLayoutAttributeCenterYWithinMargins NS_ENUM_AVAILABLE_IOS(8_0),
    
    NSLayoutAttributeNotAnAttribute = 0
};

typedef NS_OPTIONS(NSUInteger, NSLayoutFormatOptions) {
    NSLayoutFormatAlignAllLeft = (1 << NSLayoutAttributeLeft),
    NSLayoutFormatAlignAllRight = (1 << NSLayoutAttributeRight),
    NSLayoutFormatAlignAllTop = (1 << NSLayoutAttributeTop),
    NSLayoutFormatAlignAllBottom = (1 << NSLayoutAttributeBottom),
    NSLayoutFormatAlignAllLeading = (1 << NSLayoutAttributeLeading),
    NSLayoutFormatAlignAllTrailing = (1 << NSLayoutAttributeTrailing),
    NSLayoutFormatAlignAllCenterX = (1 << NSLayoutAttributeCenterX),
    NSLayoutFormatAlignAllCenterY = (1 << NSLayoutAttributeCenterY),
    NSLayoutFormatAlignAllLastBaseline = (1 << NSLayoutAttributeLastBaseline),
    NSLayoutFormatAlignAllBaseline NS_SWIFT_UNAVAILABLE("Use 'alignAllLastBaseline' instead") = NSLayoutFormatAlignAllLastBaseline,
    NSLayoutFormatAlignAllFirstBaseline NS_ENUM_AVAILABLE_IOS(8_0) = (1 << NSLayoutAttributeFirstBaseline),
    
    NSLayoutFormatAlignmentMask = 0xFFFF,
    
    /* choose only one of these three
     */
    NSLayoutFormatDirectionLeadingToTrailing = 0 << 16, // default
    NSLayoutFormatDirectionLeftToRight = 1 << 16,
    NSLayoutFormatDirectionRightToLeft = 2 << 16,  
    
    NSLayoutFormatDirectionMask = 0x3 << 16,  
    
    /* choose only one spacing format
     */
    NSLayoutFormatSpacingEdgeToEdge API_AVAILABLE(ios(11.0),tvos(11.0)) = 0 << 19, // default
    
    /* Valid only for vertical layouts. Between views with text content the value
     will be used to determine the distance from the last baseline of the view above
     to the first baseline of the view below. For views without text content the top
     or bottom edge will be used in lieu of the baseline position.
     The default spacing "]-[" will be determined from the line heights of the fonts
     involved in views with text content, when present.
     */
    NSLayoutFormatSpacingBaselineToBaseline API_AVAILABLE(ios(11.0),tvos(11.0)) = 1 << 19,
    
    NSLayoutFormatSpacingMask API_AVAILABLE(ios(11.0),tvos(11.0)) = 0x1 << 19,
};

typedef float UILayoutPriority NS_TYPED_EXTENSIBLE_ENUM;
static const UILayoutPriority UILayoutPriorityRequired NS_AVAILABLE_IOS(6_0) = 1000; // A required constraint.  Do not exceed this.
static const UILayoutPriority UILayoutPriorityDefaultHigh NS_AVAILABLE_IOS(6_0) = 750; // This is the priority level with which a button resists compressing its content.
static const UILayoutPriority UILayoutPriorityDefaultLow NS_AVAILABLE_IOS(6_0) = 250; // This is the priority level at which a button hugs its contents horizontally.
static const UILayoutPriority UILayoutPriorityFittingSizeLevel NS_AVAILABLE_IOS(6_0) = 50; // When you send -[UIView systemLayoutSizeFittingSize:], the size fitting most closely to the target size (the argument) is computed.  UILayoutPriorityFittingSizeLevel is the priority level with which the view wants to conform to the target size in that computation.  It's quite low.  It is generally not appropriate to make a constraint at exactly this priority.  You want to be higher or lower.

NS_CLASS_AVAILABLE_IOS(6_0)
@interface NSLayoutConstraint : NSObject

/* Create an array of constraints using an ASCII art-like visual format string.
 */
+ (NSArray<__kindof NSLayoutConstraint *> *)constraintsWithVisualFormat:(NSString *)format options:(NSLayoutFormatOptions)opts metrics:(nullable NSDictionary<NSString *,id> *)metrics views:(NSDictionary<NSString *, id> *)views;

/* This macro is a helper for making view dictionaries for +constraintsWithVisualFormat:options:metrics:views:.  
 NSDictionaryOfVariableBindings(v1, v2, v3) is equivalent to [NSDictionary dictionaryWithObjectsAndKeys:v1, @"v1", v2, @"v2", v3, @"v3", nil];
 */
#define NSDictionaryOfVariableBindings(...) _NSDictionaryOfVariableBindings(@"" # __VA_ARGS__, __VA_ARGS__, nil)
UIKIT_EXTERN  NSDictionary *_NSDictionaryOfVariableBindings(NSString *commaSeparatedKeysString, __nullable id firstValue, ...) NS_AVAILABLE_IOS(6_0); // not for direct use


/* Create constraints explicitly.  Constraints are of the form "view1.attr1 = view2.attr2 * multiplier + constant" 
 If your equation does not have a second view and attribute, use nil and NSLayoutAttributeNotAnAttribute.
 */
+(instancetype)constraintWithItem:(id)view1 attribute:(NSLayoutAttribute)attr1 relatedBy:(NSLayoutRelation)relation toItem:(nullable id)view2 attribute:(NSLayoutAttribute)attr2 multiplier:(CGFloat)multiplier constant:(CGFloat)c;

/* If a constraint's priority level is less than UILayoutPriorityRequired, then it is optional.  Higher priority constraints are met before lower priority constraints.
 Constraint satisfaction is not all or nothing.  If a constraint 'a == b' is optional, that means we will attempt to minimize 'abs(a-b)'.
 This property may only be modified as part of initial set up or when optional.  After a constraint has been added to a view, an exception will be thrown if the priority is changed from/to NSLayoutPriorityRequired.
 */
@property UILayoutPriority priority;

/* When a view is archived, it archives some but not all constraints in its -constraints array.  The value of shouldBeArchived informs UIView if a particular constraint should be archived by UIView.
 If a constraint is created at runtime in response to the state of the object, it isn't appropriate to archive the constraint - rather you archive the state that gives rise to the constraint.  Since the majority of constraints that should be archived are created in Interface Builder (which is smart enough to set this prop to YES), the default value for this property is NO.
 */
@property BOOL shouldBeArchived;

/* accessors
 firstItem.firstAttribute {==,<=,>=} secondItem.secondAttribute * multiplier + constant
 Access to these properties is not recommended. Use the `firstAnchor` and `secondAnchor` properties instead.
 */
@property (nullable, readonly, assign) id firstItem;
@property (readonly) NSLayoutAttribute firstAttribute;
@property (nullable, readonly, assign) id secondItem;
@property (readonly) NSLayoutAttribute secondAttribute;

/* accessors
 firstAnchor{==,<=,>=} secondAnchor * multiplier + constant
 */
@property (readonly, copy) NSLayoutAnchor *firstAnchor NS_AVAILABLE(10_12, 10_0);
@property (readonly, copy, nullable) NSLayoutAnchor *secondAnchor NS_AVAILABLE(10_12, 10_0);
@property (readonly) NSLayoutRelation relation;
@property (readonly) CGFloat multiplier;

/* Unlike the other properties, the constant may be modified after constraint creation.  Setting the constant on an existing constraint performs much better than removing the constraint and adding a new one that's just like the old but for having a new constant.
 */
@property CGFloat constant;

/* The receiver may be activated or deactivated by manipulating this property.  Only active constraints affect the calculated layout.  Attempting to activate a constraint whose items have no common ancestor will cause an exception to be thrown.  Defaults to NO for newly created constraints. */
@property (getter=isActive) BOOL active NS_AVAILABLE(10_10, 8_0);

/* Convenience method that activates each constraint in the contained array, in the same manner as setting active=YES. This is often more efficient than activating each constraint individually. */
+ (void)activateConstraints:(NSArray<NSLayoutConstraint *> *)constraints NS_AVAILABLE(10_10, 8_0);

/* Convenience method that deactivates each constraint in the contained array, in the same manner as setting active=NO. This is often more efficient than deactivating each constraint individually. */
+ (void)deactivateConstraints:(NSArray<NSLayoutConstraint *> *)constraints NS_AVAILABLE(10_10, 8_0);
@end

@interface NSLayoutConstraint (NSIdentifier)
/* For ease in debugging, name a constraint by setting its identifier, which will be printed in the constraint's description.
 Identifiers starting with UI and NS are reserved by the system.
 */
@property (nullable, copy) NSString *identifier NS_AVAILABLE_IOS(7_0);

@end

/*
 UILayoutSupport protocol is implemented by layout guide objects
 returned by UIViewController properties topLayoutGuide and bottomLayoutGuide.
 These guide objects may be used as layout items in the NSLayoutConstraint
 factory methods.
 */
@class NSLayoutYAxisAnchor, NSLayoutDimension;
@protocol UILayoutSupport <NSObject>
@property(nonatomic,readonly) CGFloat length;  // As a courtesy when not using auto layout, this value is safe to refer to in -viewDidLayoutSubviews, or in -layoutSubviews after calling super

/* Constraint creation conveniences. See NSLayoutAnchor.h for details.
 */
@property(readonly, strong) NSLayoutYAxisAnchor *topAnchor NS_AVAILABLE_IOS(9_0);
@property(readonly, strong) NSLayoutYAxisAnchor *bottomAnchor NS_AVAILABLE_IOS(9_0);
@property(readonly, strong) NSLayoutDimension *heightAnchor NS_AVAILABLE_IOS(9_0);
@end

NS_ASSUME_NONNULL_END

