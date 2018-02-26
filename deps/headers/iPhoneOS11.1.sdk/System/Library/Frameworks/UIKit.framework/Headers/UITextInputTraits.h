//
//  UITextInputTraits.h
//  UIKit
//
//  Copyright (c) 2006-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>

//
// UITextAutocapitalizationType
//
// Controls autocapitalization behavior for a text widget.
// Note: Capitalization does not apply in all script systems. In such
// cases, these values are ignored by the keyboard/input method implementation.
//
typedef NS_ENUM(NSInteger, UITextAutocapitalizationType) {
    UITextAutocapitalizationTypeNone,
    UITextAutocapitalizationTypeWords,
    UITextAutocapitalizationTypeSentences,
    UITextAutocapitalizationTypeAllCharacters,
};

//
// UITextAutocorrectionType
//
// Controls keyboard autocorrection behavior for a text widget.
// Note: Some input methods do not support inline autocorrection, and 
// instead use a conversion and/or candidate selection methodology. In such
// cases, these values are ignored by the keyboard/input method implementation.
//
typedef NS_ENUM(NSInteger, UITextAutocorrectionType) {
    UITextAutocorrectionTypeDefault,
    UITextAutocorrectionTypeNo,
    UITextAutocorrectionTypeYes,
};

//
// UITextSpellCheckingType
//
// Controls the annotation of misspelled words for a text widget.
// Note: Some input methods do not support spell checking.
typedef NS_ENUM(NSInteger, UITextSpellCheckingType) {
    UITextSpellCheckingTypeDefault,
    UITextSpellCheckingTypeNo,
    UITextSpellCheckingTypeYes,
} NS_ENUM_AVAILABLE_IOS(5_0);

//
// UITextSmartQuotesType
//
// Controls the automatic conversion of typographic quote characters for a text widget.
typedef NS_ENUM(NSInteger, UITextSmartQuotesType) {
    UITextSmartQuotesTypeDefault,
    UITextSmartQuotesTypeNo,
    UITextSmartQuotesTypeYes,
} NS_ENUM_AVAILABLE_IOS(11_0);

//
// UITextSmartDashesType
//
// Controls the automatic conversion of hyphens into en/em-dashes for a text widget.
typedef NS_ENUM(NSInteger, UITextSmartDashesType) {
    UITextSmartDashesTypeDefault,
    UITextSmartDashesTypeNo,
    UITextSmartDashesTypeYes,
} NS_ENUM_AVAILABLE_IOS(11_0);

//
// UITextSmartInsertDeleteType
//
// Controls the automatic insertion/removal of spaces for a text widget.
typedef NS_ENUM(NSInteger, UITextSmartInsertDeleteType) {
    UITextSmartInsertDeleteTypeDefault,
    UITextSmartInsertDeleteTypeNo,
    UITextSmartInsertDeleteTypeYes,
} NS_ENUM_AVAILABLE_IOS(11_0);

//
// UIKeyboardType
//
// Requests that a particular keyboard type be displayed when a text widget
// becomes first responder. 
// Note: Some keyboard/input methods types may not support every variant. 
// In such cases, the input method will make a best effort to find a close 
// match to the requested type (e.g. displaying UIKeyboardTypeNumbersAndPunctuation 
// type if UIKeyboardTypeNumberPad is not supported).
//
typedef NS_ENUM(NSInteger, UIKeyboardType) {
    UIKeyboardTypeDefault,                // Default type for the current input method.
    UIKeyboardTypeASCIICapable,           // Displays a keyboard which can enter ASCII characters
    UIKeyboardTypeNumbersAndPunctuation,  // Numbers and assorted punctuation.
    UIKeyboardTypeURL,                    // A type optimized for URL entry (shows . / .com prominently).
    UIKeyboardTypeNumberPad,              // A number pad with locale-appropriate digits (0-9, ۰-۹, ०-९, etc.). Suitable for PIN entry.
    UIKeyboardTypePhonePad,               // A phone pad (1-9, *, 0, #, with letters under the numbers).
    UIKeyboardTypeNamePhonePad,           // A type optimized for entering a person's name or phone number.
    UIKeyboardTypeEmailAddress,           // A type optimized for multiple email address entry (shows space @ . prominently).
    UIKeyboardTypeDecimalPad NS_ENUM_AVAILABLE_IOS(4_1),   // A number pad with a decimal point.
    UIKeyboardTypeTwitter NS_ENUM_AVAILABLE_IOS(5_0),      // A type optimized for twitter text entry (easy access to @ #)
    UIKeyboardTypeWebSearch NS_ENUM_AVAILABLE_IOS(7_0),    // A default keyboard type with URL-oriented addition (shows space . prominently).
    UIKeyboardTypeASCIICapableNumberPad NS_ENUM_AVAILABLE_IOS(10_0), // A number pad (0-9) that will always be ASCII digits.

    UIKeyboardTypeAlphabet = UIKeyboardTypeASCIICapable, // Deprecated

};

//
// UIKeyboardAppearance
//
// Requests a keyboard appearance be used when a text widget
// becomes first responder.. 
// Note: Some keyboard/input methods types may not support every variant. 
// In such cases, the input method will make a best effort to find a close 
// match to the requested type.
//
typedef NS_ENUM(NSInteger, UIKeyboardAppearance) {
    UIKeyboardAppearanceDefault,          // Default apperance for the current input method.
    UIKeyboardAppearanceDark NS_ENUM_AVAILABLE_IOS(7_0),
    UIKeyboardAppearanceLight NS_ENUM_AVAILABLE_IOS(7_0),
    UIKeyboardAppearanceAlert = UIKeyboardAppearanceDark,  // Deprecated
};

//
// UIReturnKeyType
//
// Controls the display of the return key. 
//
// Note: This enum is under discussion and may be replaced with a 
// different implementation.
//
typedef NS_ENUM(NSInteger, UIReturnKeyType) {
    UIReturnKeyDefault,
    UIReturnKeyGo,
    UIReturnKeyGoogle,
    UIReturnKeyJoin,
    UIReturnKeyNext,
    UIReturnKeyRoute,
    UIReturnKeySearch,
    UIReturnKeySend,
    UIReturnKeyYahoo,
    UIReturnKeyDone,
    UIReturnKeyEmergencyCall,
    UIReturnKeyContinue NS_ENUM_AVAILABLE_IOS(9_0),
};

#if UIKIT_STRING_ENUMS
typedef NSString * UITextContentType NS_EXTENSIBLE_STRING_ENUM;
#else
typedef NSString * UITextContentType;
#endif

//
// UITextInputTraits
//
// Controls features of text widgets (or other custom objects that might wish 
// to respond to keyboard input).
//
@protocol UITextInputTraits <NSObject>

@optional

@property(nonatomic) UITextAutocapitalizationType autocapitalizationType; // default is UITextAutocapitalizationTypeSentences
@property(nonatomic) UITextAutocorrectionType autocorrectionType;         // default is UITextAutocorrectionTypeDefault
@property(nonatomic) UITextSpellCheckingType spellCheckingType NS_AVAILABLE_IOS(5_0); // default is UITextSpellCheckingTypeDefault;
@property(nonatomic) UITextSmartQuotesType smartQuotesType NS_AVAILABLE_IOS(11_0); // default is UITextSmartQuotesTypeDefault;
@property(nonatomic) UITextSmartDashesType smartDashesType NS_AVAILABLE_IOS(11_0); // default is UITextSmartDashesTypeDefault;
@property(nonatomic) UITextSmartInsertDeleteType smartInsertDeleteType NS_AVAILABLE_IOS(11_0); // default is UITextSmartInsertDeleteTypeDefault;
@property(nonatomic) UIKeyboardType keyboardType;                         // default is UIKeyboardTypeDefault
@property(nonatomic) UIKeyboardAppearance keyboardAppearance;             // default is UIKeyboardAppearanceDefault
@property(nonatomic) UIReturnKeyType returnKeyType;                       // default is UIReturnKeyDefault (See note under UIReturnKeyType enum)
@property(nonatomic) BOOL enablesReturnKeyAutomatically;                  // default is NO (when YES, will automatically disable return key when text widget has zero-length contents, and will automatically enable when text widget has non-zero-length contents)
@property(nonatomic,getter=isSecureTextEntry) BOOL secureTextEntry;       // default is NO

// The textContentType property is to provide the keyboard with extra information about the semantic intent of the text document.
@property(nonatomic,copy) UITextContentType textContentType NS_AVAILABLE_IOS(10_0); // default is nil

@end


UIKIT_EXTERN UITextContentType const UITextContentTypeName                      NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeNamePrefix                NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeGivenName                 NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeMiddleName                NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeFamilyName                NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeNameSuffix                NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeNickname                  NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeJobTitle                  NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeOrganizationName          NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeLocation                  NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeFullStreetAddress         NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeStreetAddressLine1        NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeStreetAddressLine2        NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeAddressCity               NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeAddressState              NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeAddressCityAndState       NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeSublocality               NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeCountryName               NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypePostalCode                NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeTelephoneNumber           NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeEmailAddress              NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeURL                       NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeCreditCardNumber          NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN UITextContentType const UITextContentTypeUsername                  NS_AVAILABLE_IOS(11_0);
UIKIT_EXTERN UITextContentType const UITextContentTypePassword                  NS_AVAILABLE_IOS(11_0);

