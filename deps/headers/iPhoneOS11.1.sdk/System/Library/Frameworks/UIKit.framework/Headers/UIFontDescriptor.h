//
//  UIFontDescriptor.h
//  UIKit
//
//  Copyright (c) 2013-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UIKit/UIKitDefines.h>


NS_ASSUME_NONNULL_BEGIN

typedef NS_OPTIONS(uint32_t, UIFontDescriptorSymbolicTraits) {
    /* Symbolic Font Traits (Typeface info - lower 16 bits of UIFontDescriptorSymbolicTraits) */
    /*
     UIFontDescriptorSymbolicTraits symbolically describes stylistic aspects of a font. The upper 16 bits is used to describe appearance of the font whereas the lower 16 bits for typeface. The font appearance information represented by the upper 16 bits can be used for stylistic font matching.
     */
    UIFontDescriptorTraitItalic = 1u << 0,
    UIFontDescriptorTraitBold = 1u << 1,
    UIFontDescriptorTraitExpanded = 1u << 5, // expanded and condensed traits are mutually exclusive
    UIFontDescriptorTraitCondensed = 1u << 6,
    UIFontDescriptorTraitMonoSpace = 1u << 10, // Use fixed-pitch glyphs if available. May have multiple glyph advances (most CJK glyphs may contain two spaces)
    UIFontDescriptorTraitVertical = 1u << 11, // Use vertical glyph variants and metrics
    UIFontDescriptorTraitUIOptimized = 1u << 12, // Synthesize appropriate attributes for UI rendering such as control titles if necessary
    UIFontDescriptorTraitTightLeading = 1u << 15, // Use tighter leading values
    UIFontDescriptorTraitLooseLeading = 1u << 16, // Use looser leading values
    
    /* Font appearance info (upper 16 bits of NSFontSymbolicTraits */
    /* UIFontDescriptorClassFamily classifies certain stylistic qualities of the font. These values correspond closely to the font class values in the OpenType 'OS/2' table. The class values are bundled in the upper four bits of the UIFontDescriptorSymbolicTraits and can be accessed via UIFontDescriptorClassMask. For specific meaning of each identifier, refer to the OpenType specification.
     */
    UIFontDescriptorClassMask = 0xF0000000,
    
    UIFontDescriptorClassUnknown = 0u << 28,
    UIFontDescriptorClassOldStyleSerifs = 1u << 28,
    UIFontDescriptorClassTransitionalSerifs = 2u << 28,
    UIFontDescriptorClassModernSerifs = 3u << 28,
    UIFontDescriptorClassClarendonSerifs = 4u << 28,
    UIFontDescriptorClassSlabSerifs = 5u << 28,
    UIFontDescriptorClassFreeformSerifs = 7u << 28,
    UIFontDescriptorClassSansSerif = 8u << 28,
    UIFontDescriptorClassOrnamentals = 9u << 28,
    UIFontDescriptorClassScripts = 10u << 28,
    UIFontDescriptorClassSymbolic = 12u << 28
} NS_ENUM_AVAILABLE_IOS(7_0);

typedef NSUInteger UIFontDescriptorClass;
#if UIKIT_STRING_ENUMS
typedef NSString * UIFontTextStyle NS_EXTENSIBLE_STRING_ENUM;
#else
typedef NSString * UIFontTextStyle;
#endif
typedef NSString * UIFontDescriptorAttributeName NS_EXTENSIBLE_STRING_ENUM;
typedef NSString * UIFontDescriptorTraitKey NS_STRING_ENUM;
typedef NSString * UIFontDescriptorFeatureKey NS_EXTENSIBLE_STRING_ENUM;
typedef CGFloat UIFontWeight _NS_TYPED_EXTENSIBLE_ENUM;

@class NSMutableDictionary, NSDictionary, NSArray, NSSet, UITraitCollection;

NS_CLASS_AVAILABLE_IOS(7_0) @interface UIFontDescriptor : NSObject <NSCopying, NSSecureCoding>

- (instancetype)init;
- (nullable instancetype)initWithCoder:(NSCoder *)aDecoder NS_DESIGNATED_INITIALIZER;

// Core attribute access
@property(nonatomic, readonly) NSString *postscriptName;
@property(nonatomic, readonly) CGFloat   pointSize;
@property(nonatomic, readonly) CGAffineTransform matrix;
@property(nonatomic, readonly) UIFontDescriptorSymbolicTraits symbolicTraits;

- (nullable id)objectForKey:(UIFontDescriptorAttributeName)anAttribute;

#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly) NSDictionary<UIFontDescriptorAttributeName, id> *fontAttributes;
#else
- (NSDictionary<UIFontDescriptorAttributeName, id> *)fontAttributes;
#endif

// Instance conversion
// Returns "normalized" font descriptors matching the receiver. mandatoryKeys is an NSSet instance containing keys that are required to be identical in order to be matched. mandatoryKeys can be nil.
- (NSArray<UIFontDescriptor *> *)matchingFontDescriptorsWithMandatoryKeys:(nullable NSSet<UIFontDescriptorAttributeName> *)mandatoryKeys;

// Instantiation
+ (UIFontDescriptor *)fontDescriptorWithFontAttributes:(NSDictionary<UIFontDescriptorAttributeName, id> *)attributes;
+ (UIFontDescriptor *)fontDescriptorWithName:(NSString *)fontName size:(CGFloat)size;
+ (UIFontDescriptor *)fontDescriptorWithName:(NSString *)fontName matrix:(CGAffineTransform)matrix;

// Returns a font descriptor containing the text style and containing the user's selected content size category.
+ (UIFontDescriptor *)preferredFontDescriptorWithTextStyle:(UIFontTextStyle)style;
// Returns a font descriptor containing the text style and containing the content size category defined in the trait collection.
+ (UIFontDescriptor *)preferredFontDescriptorWithTextStyle:(UIFontTextStyle)style compatibleWithTraitCollection:(nullable UITraitCollection *)traitCollection NS_AVAILABLE_IOS(10_0) __WATCHOS_PROHIBITED;

- (instancetype)initWithFontAttributes:(NSDictionary<UIFontDescriptorAttributeName, id> *)attributes NS_DESIGNATED_INITIALIZER;

- (UIFontDescriptor *)fontDescriptorByAddingAttributes:(NSDictionary<UIFontDescriptorAttributeName, id> *)attributes; // the new attributes take precedence over the existing ones in the receiver
- (UIFontDescriptor *)fontDescriptorWithSize:(CGFloat)newPointSize;
- (UIFontDescriptor *)fontDescriptorWithMatrix:(CGAffineTransform)matrix;
- (UIFontDescriptor *)fontDescriptorWithFace:(NSString *)newFace;
- (UIFontDescriptor *)fontDescriptorWithFamily:(NSString *)newFamily;

- (nullable UIFontDescriptor *)fontDescriptorWithSymbolicTraits:(UIFontDescriptorSymbolicTraits)symbolicTraits; // Returns a new font descriptor reference in the same family with the given symbolic traits, or nil if none found in the system.


@end

// Predefined font attributes not defined in NSAttributedString.h

UIKIT_EXTERN UIFontDescriptorAttributeName const UIFontDescriptorFamilyAttribute NS_AVAILABLE_IOS(7_0);
UIKIT_EXTERN UIFontDescriptorAttributeName const UIFontDescriptorNameAttribute NS_AVAILABLE_IOS(7_0);
UIKIT_EXTERN UIFontDescriptorAttributeName const UIFontDescriptorFaceAttribute NS_AVAILABLE_IOS(7_0);
UIKIT_EXTERN UIFontDescriptorAttributeName const UIFontDescriptorSizeAttribute NS_AVAILABLE_IOS(7_0);
UIKIT_EXTERN UIFontDescriptorAttributeName const UIFontDescriptorVisibleNameAttribute NS_AVAILABLE_IOS(7_0);

UIKIT_EXTERN UIFontDescriptorAttributeName const UIFontDescriptorMatrixAttribute NS_AVAILABLE_IOS(7_0); // An NSValue containing a CGAffineTransform. (default: identity matrix)
UIKIT_EXTERN UIFontDescriptorAttributeName const UIFontDescriptorCharacterSetAttribute NS_AVAILABLE_IOS(7_0); // An NSCharacterSet instance representing a set of Unicode characters covered by the font. (default: supplied by font)
UIKIT_EXTERN UIFontDescriptorAttributeName const UIFontDescriptorCascadeListAttribute NS_AVAILABLE_IOS(7_0); // An NSArray instance. Each member of the array is a sub-descriptor. (default: the system default cascading list for user's locale)
UIKIT_EXTERN UIFontDescriptorAttributeName const UIFontDescriptorTraitsAttribute NS_AVAILABLE_IOS(7_0); // An NSDictionary instance fully describing font traits. (default: supplied by font)
UIKIT_EXTERN UIFontDescriptorAttributeName const UIFontDescriptorFixedAdvanceAttribute NS_AVAILABLE_IOS(7_0); // A float represented as an NSNumber. The value overrides glyph advancement specified by the font. (default: supplied by each glyph)
UIKIT_EXTERN UIFontDescriptorAttributeName const UIFontDescriptorFeatureSettingsAttribute NS_AVAILABLE_IOS(7_0); // An array of dictionaries representing non-default font feature settings. Each dictionary contains UIFontFeatureTypeIdentifierKey and UIFontFeatureSelectorIdentifierKey.

// An NSString containing the desired Text Style
UIKIT_EXTERN UIFontDescriptorAttributeName const UIFontDescriptorTextStyleAttribute NS_AVAILABLE_IOS(7_0);
    
// Font traits keys
// This key is used with a trait dictionary to get the symbolic traits value as an NSNumber.
UIKIT_EXTERN UIFontDescriptorAttributeName const UIFontSymbolicTrait NS_AVAILABLE_IOS(7_0);

// This key is used with a trait dictionary to get the normalized weight value as an NSNumber. The valid value range is from -1.0 to 1.0. The value of 0.0 corresponds to the regular or medium font weight.
UIKIT_EXTERN UIFontDescriptorTraitKey const UIFontWeightTrait NS_AVAILABLE_IOS(7_0);

// This key is used with a trait dictionary to get the relative inter-glyph spacing value as an NSNumber. The valid value range is from -1.0 to 1.0. The value of 0.0 corresponds to the regular glyph spacing.
UIKIT_EXTERN UIFontDescriptorTraitKey const UIFontWidthTrait NS_AVAILABLE_IOS(7_0);

// This key is used with a trait dictionary to get the relative slant angle value as an NSNumber. The valid value range is from -1.0 to 1.0. The value or 0.0 corresponds to 0 degree clockwise rotation from the vertical and 1.0 corresponds to 30 degrees clockwise rotation.
UIKIT_EXTERN UIFontDescriptorTraitKey const UIFontSlantTrait NS_AVAILABLE_IOS(7_0);

// Suggested values for use with UIFontWeightTrait, and UIFont's systemFontOfSize:weight:
// Beware that most fonts will _not_ have variants available in all these weights!
UIKIT_EXTERN const UIFontWeight UIFontWeightUltraLight NS_AVAILABLE_IOS(8_2);
UIKIT_EXTERN const UIFontWeight UIFontWeightThin NS_AVAILABLE_IOS(8_2);
UIKIT_EXTERN const UIFontWeight UIFontWeightLight NS_AVAILABLE_IOS(8_2);
UIKIT_EXTERN const UIFontWeight UIFontWeightRegular NS_AVAILABLE_IOS(8_2);
UIKIT_EXTERN const UIFontWeight UIFontWeightMedium NS_AVAILABLE_IOS(8_2);
UIKIT_EXTERN const UIFontWeight UIFontWeightSemibold NS_AVAILABLE_IOS(8_2);
UIKIT_EXTERN const UIFontWeight UIFontWeightBold NS_AVAILABLE_IOS(8_2);
UIKIT_EXTERN const UIFontWeight UIFontWeightHeavy NS_AVAILABLE_IOS(8_2);
UIKIT_EXTERN const UIFontWeight UIFontWeightBlack NS_AVAILABLE_IOS(8_2);

// Font feature keys
// A number object specifying font feature type such as ligature, character shape, etc.
UIKIT_EXTERN UIFontDescriptorFeatureKey const UIFontFeatureTypeIdentifierKey NS_AVAILABLE_IOS(7_0);

// A number object specifying font feature selector such as common ligature off, traditional character shape, etc.
UIKIT_EXTERN UIFontDescriptorFeatureKey const UIFontFeatureSelectorIdentifierKey NS_AVAILABLE_IOS(7_0);

// Font text styles, semantic descriptions of the intended use for a font returned by +[UIFont preferredFontForTextStyle:]
UIKIT_EXTERN UIFontTextStyle const UIFontTextStyleLargeTitle API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, tvos);
UIKIT_EXTERN UIFontTextStyle const UIFontTextStyleTitle1 NS_AVAILABLE_IOS(9_0);
UIKIT_EXTERN UIFontTextStyle const UIFontTextStyleTitle2 NS_AVAILABLE_IOS(9_0);
UIKIT_EXTERN UIFontTextStyle const UIFontTextStyleTitle3 NS_AVAILABLE_IOS(9_0);
UIKIT_EXTERN UIFontTextStyle const UIFontTextStyleHeadline NS_AVAILABLE_IOS(7_0);
UIKIT_EXTERN UIFontTextStyle const UIFontTextStyleSubheadline NS_AVAILABLE_IOS(7_0);
UIKIT_EXTERN UIFontTextStyle const UIFontTextStyleBody NS_AVAILABLE_IOS(7_0);
UIKIT_EXTERN UIFontTextStyle const UIFontTextStyleCallout NS_AVAILABLE_IOS(9_0);
UIKIT_EXTERN UIFontTextStyle const UIFontTextStyleFootnote NS_AVAILABLE_IOS(7_0);
UIKIT_EXTERN UIFontTextStyle const UIFontTextStyleCaption1 NS_AVAILABLE_IOS(7_0);
UIKIT_EXTERN UIFontTextStyle const UIFontTextStyleCaption2 NS_AVAILABLE_IOS(7_0);

NS_ASSUME_NONNULL_END

