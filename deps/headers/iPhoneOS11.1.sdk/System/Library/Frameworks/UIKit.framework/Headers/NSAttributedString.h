//
//  NSAttributedString.h
//  UIKit
//
//  Copyright (c) 2011-2017, Apple Inc. All rights reserved.
//

#import <Foundation/NSAttributedString.h>
#import <Foundation/NSItemProvider.h>
#import <UIKit/UIKitDefines.h>

@class NSAttributedString;
@class NSFileWrapper;
@class NSURL;

NS_ASSUME_NONNULL_BEGIN
/************************ Attributes ************************/

// Predefined character attributes for text. If the key is not present in the dictionary, it indicates the default value described below.
UIKIT_EXTERN NSAttributedStringKey const NSFontAttributeName NS_AVAILABLE(10_0, 6_0);                // UIFont, default Helvetica(Neue) 12
UIKIT_EXTERN NSAttributedStringKey const NSParagraphStyleAttributeName NS_AVAILABLE(10_0, 6_0);      // NSParagraphStyle, default defaultParagraphStyle
UIKIT_EXTERN NSAttributedStringKey const NSForegroundColorAttributeName NS_AVAILABLE(10_0, 6_0);     // UIColor, default blackColor
UIKIT_EXTERN NSAttributedStringKey const NSBackgroundColorAttributeName NS_AVAILABLE(10_0, 6_0);     // UIColor, default nil: no background
UIKIT_EXTERN NSAttributedStringKey const NSLigatureAttributeName NS_AVAILABLE(10_0, 6_0);            // NSNumber containing integer, default 1: default ligatures, 0: no ligatures
UIKIT_EXTERN NSAttributedStringKey const NSKernAttributeName NS_AVAILABLE(10_0, 6_0);                // NSNumber containing floating point value, in points; amount to modify default kerning. 0 means kerning is disabled.
UIKIT_EXTERN NSAttributedStringKey const NSStrikethroughStyleAttributeName NS_AVAILABLE(10_0, 6_0);  // NSNumber containing integer, default 0: no strikethrough
UIKIT_EXTERN NSAttributedStringKey const NSUnderlineStyleAttributeName NS_AVAILABLE(10_0, 6_0);      // NSNumber containing integer, default 0: no underline
UIKIT_EXTERN NSAttributedStringKey const NSStrokeColorAttributeName NS_AVAILABLE(10_0, 6_0);         // UIColor, default nil: same as foreground color
UIKIT_EXTERN NSAttributedStringKey const NSStrokeWidthAttributeName NS_AVAILABLE(10_0, 6_0);         // NSNumber containing floating point value, in percent of font point size, default 0: no stroke; positive for stroke alone, negative for stroke and fill (a typical value for outlined text would be 3.0)
UIKIT_EXTERN NSAttributedStringKey const NSShadowAttributeName NS_AVAILABLE(10_0, 6_0);              // NSShadow, default nil: no shadow
UIKIT_EXTERN NSAttributedStringKey const NSTextEffectAttributeName NS_AVAILABLE(10_10, 7_0);          // NSString, default nil: no text effect

UIKIT_EXTERN NSAttributedStringKey const NSAttachmentAttributeName NS_AVAILABLE(10_0, 7_0);          // NSTextAttachment, default nil
UIKIT_EXTERN NSAttributedStringKey const NSLinkAttributeName NS_AVAILABLE(10_0, 7_0);                // NSURL (preferred) or NSString
UIKIT_EXTERN NSAttributedStringKey const NSBaselineOffsetAttributeName NS_AVAILABLE(10_0, 7_0);      // NSNumber containing floating point value, in points; offset from baseline, default 0
UIKIT_EXTERN NSAttributedStringKey const NSUnderlineColorAttributeName NS_AVAILABLE(10_0, 7_0);      // UIColor, default nil: same as foreground color
UIKIT_EXTERN NSAttributedStringKey const NSStrikethroughColorAttributeName NS_AVAILABLE(10_0, 7_0);  // UIColor, default nil: same as foreground color
UIKIT_EXTERN NSAttributedStringKey const NSObliquenessAttributeName NS_AVAILABLE(10_0, 7_0);         // NSNumber containing floating point value; skew to be applied to glyphs, default 0: no skew
UIKIT_EXTERN NSAttributedStringKey const NSExpansionAttributeName NS_AVAILABLE(10_0, 7_0);           // NSNumber containing floating point value; log of expansion factor to be applied to glyphs, default 0: no expansion

UIKIT_EXTERN NSAttributedStringKey const NSWritingDirectionAttributeName NS_AVAILABLE(10_6, 7_0);    // NSArray of NSNumbers representing the nested levels of writing direction overrides as defined by Unicode LRE, RLE, LRO, and RLO characters.  The control characters can be obtained by masking NSWritingDirection and NSWritingDirectionFormatType values.  LRE: NSWritingDirectionLeftToRight|NSWritingDirectionEmbedding, RLE: NSWritingDirectionRightToLeft|NSWritingDirectionEmbedding, LRO: NSWritingDirectionLeftToRight|NSWritingDirectionOverride, RLO: NSWritingDirectionRightToLeft|NSWritingDirectionOverride,

UIKIT_EXTERN NSAttributedStringKey const NSVerticalGlyphFormAttributeName NS_AVAILABLE(10_7, 6_0);   // An NSNumber containing an integer value.  0 means horizontal text.  1 indicates vertical text.  If not specified, it could follow higher-level vertical orientation settings.  Currently on iOS, it's always horizontal.  The behavior for any other value is undefined.



/************************ Attribute values ************************/
// This defines currently supported values for NSUnderlineStyleAttributeName and NSStrikethroughStyleAttributeName. NSUnderlineStyle*, NSUnderlinePattern*, and NSUnderlineByWord are or'ed together to produce an underline style.
typedef NS_ENUM(NSInteger, NSUnderlineStyle) {
    NSUnderlineStyleNone                                    = 0x00,
    NSUnderlineStyleSingle                                  = 0x01,
    NSUnderlineStyleThick NS_ENUM_AVAILABLE(10_0, 7_0)      = 0x02,
    NSUnderlineStyleDouble NS_ENUM_AVAILABLE(10_0, 7_0)     = 0x09,

    NSUnderlinePatternSolid NS_ENUM_AVAILABLE(10_0, 7_0)      = 0x0000,
    NSUnderlinePatternDot NS_ENUM_AVAILABLE(10_0, 7_0)        = 0x0100,
    NSUnderlinePatternDash NS_ENUM_AVAILABLE(10_0, 7_0)       = 0x0200,
    NSUnderlinePatternDashDot NS_ENUM_AVAILABLE(10_0, 7_0)    = 0x0300,
    NSUnderlinePatternDashDotDot NS_ENUM_AVAILABLE(10_0, 7_0) = 0x0400,

    NSUnderlineByWord NS_ENUM_AVAILABLE(10_0, 7_0)            = 0x8000
} NS_ENUM_AVAILABLE(10_0, 6_0);

// NSWritingDirectionFormatType values used by NSWritingDirectionAttributeName. It is or'ed with either NSWritingDirectionLeftToRight or NSWritingDirectionRightToLeft. Can specify the formatting controls defined by Unicode Bidirectional Algorithm.
typedef NS_ENUM(NSInteger, NSWritingDirectionFormatType) {
    NSWritingDirectionEmbedding     = (0 << 1),
    NSWritingDirectionOverride      = (1 << 1)
} NS_ENUM_AVAILABLE(10_11, 9_0);

// NSTextEffectAttributeName values
typedef NSString * NSTextEffectStyle NS_STRING_ENUM;
UIKIT_EXTERN NSTextEffectStyle const NSTextEffectLetterpressStyle NS_AVAILABLE(10_10, 7_0);


/************************ Attribute fixing ************************/

@interface NSMutableAttributedString (NSAttributedStringAttributeFixing)
// This method fixes attribute inconsistencies inside range.  It ensures NSFontAttributeName covers the characters, NSParagraphStyleAttributeName is only changing at paragraph boundaries, and NSTextAttachmentAttributeName is assigned to NSAttachmentCharacter.  NSTextStorage automatically invokes this method via -ensureAttributesAreFixedInRange:.
- (void)fixAttributesInRange:(NSRange)range NS_AVAILABLE(10_0, 7_0);

@end


/************************ Document formats ************************/

typedef NSString * NSAttributedStringDocumentType NS_EXTENSIBLE_STRING_ENUM;

// Supported document types for the NSDocumentTypeDocumentAttribute key in the document attributes dictionary.
UIKIT_EXTERN NSAttributedStringDocumentType const NSPlainTextDocumentType NS_AVAILABLE(10_0, 7_0);
UIKIT_EXTERN NSAttributedStringDocumentType const NSRTFTextDocumentType  NS_AVAILABLE(10_0, 7_0);
UIKIT_EXTERN NSAttributedStringDocumentType const NSRTFDTextDocumentType NS_AVAILABLE(10_0, 7_0);
UIKIT_EXTERN NSAttributedStringDocumentType const NSHTMLTextDocumentType  NS_AVAILABLE(10_0, 7_0);

typedef NSString * NSTextLayoutSectionKey NS_STRING_ENUM;

// Keys for NSLayoutOrientationSectionsAttribute.
UIKIT_EXTERN NSTextLayoutSectionKey const NSTextLayoutSectionOrientation NS_AVAILABLE(10_7, 7_0); // NSNumber containing NSTextLayoutOrientation value. default: NSTextLayoutOrientationHorizontal
UIKIT_EXTERN NSTextLayoutSectionKey const NSTextLayoutSectionRange NS_AVAILABLE(10_7, 7_0); // NSValue containing NSRange representing a character range. default: a range covering the whole document

typedef NSString * NSAttributedStringDocumentAttributeKey NS_EXTENSIBLE_STRING_ENUM;

// Keys for options and document attributes dictionaries.  They are in and out document properties used by both read/write methods.

UIKIT_EXTERN NSAttributedStringDocumentAttributeKey const NSDocumentTypeDocumentAttribute NS_AVAILABLE(10_0, 7_0);  // @"DocumentType", one of the document types declared above.  For reader methods, this key in options can specify the document type for interpreting the contents.  Upon return, the document attributes can contain this key for indicating the actual format used to read the contents.  For write methods, this key specifies the format for generating the data.


// NSPlainTextDocumentType document attributes
UIKIT_EXTERN NSAttributedStringDocumentAttributeKey const NSCharacterEncodingDocumentAttribute NS_AVAILABLE(10_0, 7_0);  // @"CharacterEncoding", NSNumber containing integer specifying NSStringEncoding for the file; default for plain text is the default encoding.  This key in options can specify the string encoding for reading the data.  Upon return, the document attributes can contain the actual encoding used.  For writing methods, this value is used for generating the plain text data.
UIKIT_EXTERN NSAttributedStringDocumentAttributeKey const NSDefaultAttributesDocumentAttribute NS_AVAILABLE(10_11, 7_0);  // @"DefaultAttributes", NSDictionary containing attributes to be applied to plain files.  Used by reader methods.  This key in options can specify the default attributes applied to the entire document contents.  The document attributes can contain this key indicating the actual attributes used.


// NSRTFTextDocumentType and NSRTFDTextDocumentType document attributes
// Document dimension
// They are document attributes used by read/write methods.
UIKIT_EXTERN NSAttributedStringDocumentAttributeKey const NSPaperSizeDocumentAttribute NS_AVAILABLE(10_0, 7_0);  // @"PaperSize", NSValue containing CGSize (in points)
UIKIT_EXTERN NSAttributedStringDocumentAttributeKey const NSPaperMarginDocumentAttribute NS_AVAILABLE_IOS(7_0);  // @"PaperMargin", NSValue containing UIEdgeInsets

UIKIT_EXTERN NSAttributedStringDocumentAttributeKey const NSViewSizeDocumentAttribute NS_AVAILABLE(10_0, 7_0);  // @"ViewSize", NSValue containing CGSize (in points)
UIKIT_EXTERN NSAttributedStringDocumentAttributeKey const NSViewZoomDocumentAttribute NS_AVAILABLE(10_0, 7_0);  // @"ViewZoom", NSNumber containing floating point value (100 == 100% zoom)
UIKIT_EXTERN NSAttributedStringDocumentAttributeKey const NSViewModeDocumentAttribute NS_AVAILABLE(10_0, 7_0);  // @"ViewMode", NSNumber containing integer; 0 = normal; 1 = page layout

// Document settings
// They are document attributes used by read/write methods.
UIKIT_EXTERN NSAttributedStringDocumentAttributeKey const NSReadOnlyDocumentAttribute NS_AVAILABLE(10_0, 7_0);  // @"ReadOnly", NSNumber containing integer; if missing, or 0 or negative, not readonly; 1 or more, readonly. Note that this has nothing to do with the file system protection on the file, but instead, on how the file should be displayed to the user
UIKIT_EXTERN NSAttributedStringDocumentAttributeKey const NSBackgroundColorDocumentAttribute NS_AVAILABLE(10_0, 7_0);  // @"BackgroundColor", UIColor, representing the document-wide page background color
UIKIT_EXTERN NSAttributedStringDocumentAttributeKey const NSHyphenationFactorDocumentAttribute NS_AVAILABLE(10_0, 7_0);  // @"HyphenationFactor", NSNumber containing floating point value (0=off, 1=full hyphenation)
UIKIT_EXTERN NSAttributedStringDocumentAttributeKey const NSDefaultTabIntervalDocumentAttribute NS_AVAILABLE(10_0, 7_0);  // @"DefaultTabInterval", NSNumber containing floating point value, representing the document-wide default tab stop interval, in points
UIKIT_EXTERN NSAttributedStringDocumentAttributeKey const NSTextLayoutSectionsAttribute NS_AVAILABLE(10_7, 7_0);  // NSArray of dictionaries.  Each dictionary describing a layout orientation section.  The dictionary can have two attributes: NSTextLayoutSectionOrientation and NSTextLayoutSectionRange.  When there is a gap between sections, it's assumed to have NSTextLayoutOrientationHorizontal.


typedef NSString * NSAttributedStringDocumentReadingOptionKey NS_EXTENSIBLE_STRING_ENUM;

UIKIT_EXTERN NSAttributedStringDocumentReadingOptionKey const NSDocumentTypeDocumentOption;  // @"DocumentType", NSString indicating a document type to be forced when loading the document, specified as one of the NSDocumentTypeDocumentAttribute constants listed above
UIKIT_EXTERN NSAttributedStringDocumentReadingOptionKey const NSDefaultAttributesDocumentOption;  // @"DefaultAttributes", for plain text only; NSDictionary containing attributes to be applied to plain files
UIKIT_EXTERN NSAttributedStringDocumentReadingOptionKey const NSCharacterEncodingDocumentOption;  // @"CharacterEncoding", for plain text and HTML; NSNumber containing integer specifying NSStringEncoding to be used to interpret the file



@interface NSAttributedString (NSAttributedStringDocumentFormats)
// Methods initializing the receiver contents with an external document data.  options specify document attributes for interpreting the document contents.  NSDocumentTypeDocumentAttribute, NSCharacterEncodingDocumentAttribute, and NSDefaultAttributesDocumentAttribute are supported options key.  When they are not specified, these methods will examine the data and do their best to detect the appropriate attributes.  If dict is non-NULL, it will return a dictionary with various document-wide attributes accessible via NS...DocumentAttribute keys.
- (nullable instancetype)initWithURL:(NSURL *)url options:(NSDictionary<NSAttributedStringDocumentReadingOptionKey, id> *)options documentAttributes:(NSDictionary<NSAttributedStringDocumentAttributeKey, id> * __nullable * __nullable)dict error:(NSError **)error NS_AVAILABLE(10_4, 9_0);
- (nullable instancetype)initWithData:(NSData *)data options:(NSDictionary<NSAttributedStringDocumentReadingOptionKey, id> *)options documentAttributes:(NSDictionary<NSAttributedStringDocumentAttributeKey, id> * __nullable * __nullable)dict error:(NSError **)error NS_AVAILABLE(10_0, 7_0);

// Generates an NSData object for the receiver contents in range.  It requires a document attributes dict specifying at least the NSDocumentTypeDocumentAttribute to determine the format to be written.
- (nullable NSData *)dataFromRange:(NSRange)range documentAttributes:(NSDictionary<NSAttributedStringDocumentAttributeKey, id> *)dict error:(NSError **)error NS_AVAILABLE(10_0, 7_0);

// Returns an NSFileWrapper object for the receiver contents in range.  It requires a document attributes dict specifying at least the NSDocumentTypeDocumentAttribute to determine the format to be written.  The method returns a directory file wrapper for those document types represented by a file package such as NSRTFDTextDocumentType; otherwise, it returns a regular-file file wrapper.
- (nullable NSFileWrapper *)fileWrapperFromRange:(NSRange)range documentAttributes:(NSDictionary<NSAttributedStringDocumentAttributeKey, id> *)dict error:(NSError **)error NS_AVAILABLE(10_0, 7_0);

@end

@interface NSMutableAttributedString (NSMutableAttributedStringDocumentFormats)
// Methods replacing the receiver contents with an external document data.  options specify document attributes for interpreting the document contents.  NSDocumentTypeDocumentAttribute, NSCharacterEncodingDocumentAttribute, and NSDefaultAttributesDocumentAttribute are supported options key.  When they are not specified, these methods will examine the data and do their best to detect the appropriate attributes.  If dict is non-NULL, it will return a dictionary with various document-wide attributes accessible via NS...DocumentAttribute keys.
- (BOOL)readFromURL:(NSURL *)url options:(NSDictionary<NSAttributedStringDocumentReadingOptionKey, id> *)opts documentAttributes:(NSDictionary<NSAttributedStringDocumentAttributeKey, id> * __nullable * __nullable)dict error:(NSError **)error  API_AVAILABLE(macosx(10.5), ios(9.0), watchos(2.0), tvos(9.0));
- (BOOL)readFromData:(NSData *)data options:(NSDictionary<NSAttributedStringDocumentReadingOptionKey, id> *)opts documentAttributes:(NSDictionary<NSAttributedStringDocumentAttributeKey, id> * __nullable * __nullable)dict error:(NSError **)error NS_AVAILABLE(10_0, 7_0);
@end


/************************ Misc methods ************************/
@interface NSAttributedString (NSAttributedStringKitAdditions)
// Returns YES if the receiver contains a property configured (NSAttachmentAttributeName with NSAttachmentCharacter) in range
- (BOOL)containsAttachmentsInRange:(NSRange)range NS_AVAILABLE(10_11, 9_0);
@end


@interface NSAttributedString (UINSItemProvider) <NSItemProviderReading, NSItemProviderWriting>

@end

/************************ Deprecated ************************/

typedef NS_ENUM(NSInteger, NSTextWritingDirection) {
    NSTextWritingDirectionEmbedding     = (0 << 1),
    NSTextWritingDirectionOverride      = (1 << 1)
} NS_ENUM_DEPRECATED_IOS(7_0, 9_0, "Use NSWritingDirectionFormatType instead") __TVOS_PROHIBITED;

@interface NSAttributedString(NSDeprecatedKitAdditions)
- (nullable instancetype)initWithFileURL:(NSURL *)url options:(NSDictionary *)options documentAttributes:(NSDictionary* __nullable * __nullable)dict error:(NSError **)error NS_DEPRECATED_IOS(7_0, 9_0, "Use -initWithURL:options:documentAttributes:error: instead") __TVOS_PROHIBITED;
@end

@interface NSMutableAttributedString (NSDeprecatedKitAdditions)
- (BOOL)readFromFileURL:(NSURL *)url options:(NSDictionary *)opts documentAttributes:(NSDictionary* __nullable * __nullable)dict error:(NSError **)error NS_DEPRECATED_IOS(7_0, 9_0, "Use -readFromURL:options:documentAttributes:error: instead") __TVOS_PROHIBITED;
@end
NS_ASSUME_NONNULL_END
