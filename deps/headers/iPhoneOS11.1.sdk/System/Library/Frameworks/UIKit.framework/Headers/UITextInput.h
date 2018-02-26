//
//  UITextInput.h
//  UIKit
//
//  Copyright (c) 2009-2017 Apple Inc. All rights reserved.
//

#import <CoreGraphics/CoreGraphics.h>

#import <UIKit/UITextInputTraits.h>
#import <UIKit/UIResponder.h>

//===================================================================================================
// Responders that implement the UIKeyInput protocol will be driven by the system-provided keyboard,
// which will be made available whenever a conforming responder becomes first responder.

NS_ASSUME_NONNULL_BEGIN

@protocol UIKeyInput <UITextInputTraits>

#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly) BOOL hasText;
#else
- (BOOL)hasText;
#endif
- (void)insertText:(NSString *)text;
- (void)deleteBackward;

@end

//===================================================================================================
// Responders that implement the UITextInput protocol allow the system-provided keyboard to
// offer more sophisticated behaviors based on a current selection and context.

@class NSTextAlternatives;
@class UITextPosition;
@class UITextRange;
@class UITextSelectionRect;
@class UIBarButtonItemGroup;

@protocol UITextInputTokenizer;
@protocol UITextInputDelegate;

typedef NS_ENUM(NSInteger, UITextStorageDirection) {
    UITextStorageDirectionForward = 0,
    UITextStorageDirectionBackward
};

typedef NS_ENUM(NSInteger, UITextLayoutDirection) {
    UITextLayoutDirectionRight = 2,
    UITextLayoutDirectionLeft,
    UITextLayoutDirectionUp,
    UITextLayoutDirectionDown
};

typedef NSInteger UITextDirection;

typedef NS_ENUM(NSInteger, UITextWritingDirection) {
    UITextWritingDirectionNatural = -1,
    UITextWritingDirectionLeftToRight = 0,
    UITextWritingDirectionRightToLeft,
};

typedef NS_ENUM(NSInteger, UITextGranularity) {
    UITextGranularityCharacter,
    UITextGranularityWord,
    UITextGranularitySentence,
    UITextGranularityParagraph,
    UITextGranularityLine,
    UITextGranularityDocument
};

NS_CLASS_AVAILABLE_IOS(5_1) @interface UIDictationPhrase : NSObject {
    @private
        NSString *_text;
        NSArray * __nullable _alternativeInterpretations;
}

/* -text returns the most likely interpretation for a phrase. If there are other 
 * interpretations, -alternativeInterpretations will return an array of them, with 
 * the first being most likely and the last being least likely. */
@property (nonatomic, readonly) NSString *text;
@property (nullable, nonatomic, readonly) NSArray<NSString *> *alternativeInterpretations;

@end

NS_CLASS_AVAILABLE_IOS(9_0) __TVOS_PROHIBITED __WATCHOS_PROHIBITED @interface UITextInputAssistantItem : NSObject

/// Default is YES, controls if the user is allowed to hide the shortcuts bar. Does not influence the built in auto-hiding logic.
@property (nonatomic, readwrite, assign) BOOL allowsHidingShortcuts;
/// Contains UIBarButtonItemGroups that should be displayed in the leading position on the keyboard's assistant bar.
@property (nonatomic, readwrite, copy) NSArray<UIBarButtonItemGroup *> *leadingBarButtonGroups;
/// Contains UIBarButtonItemGroups that should be displayed in the trailing position on the keyboard's assistant bar.
@property (nonatomic, readwrite, copy) NSArray<UIBarButtonItemGroup *> *trailingBarButtonGroups;

@end

@protocol UITextInput <UIKeyInput>
@required

/* Methods for manipulating text. */
- (nullable NSString *)textInRange:(UITextRange *)range;
- (void)replaceRange:(UITextRange *)range withText:(NSString *)text;

/* Text may have a selection, either zero-length (a caret) or ranged.  Editing operations are
 * always performed on the text from this selection.  nil corresponds to no selection. */

@property (nullable, readwrite, copy) UITextRange *selectedTextRange;

/* If text can be selected, it can be marked. Marked text represents provisionally
 * inserted text that has yet to be confirmed by the user.  It requires unique visual
 * treatment in its display.  If there is any marked text, the selection, whether a
 * caret or an extended range, always resides witihin.
 *
 * Setting marked text either replaces the existing marked text or, if none is present,
 * inserts it from the current selection. */ 

@property (nullable, nonatomic, readonly) UITextRange *markedTextRange; // Nil if no marked text.
@property (nullable, nonatomic, copy) NSDictionary *markedTextStyle; // Describes how the marked text should be drawn.
- (void)setMarkedText:(nullable NSString *)markedText selectedRange:(NSRange)selectedRange; // selectedRange is a range within the markedText
- (void)unmarkText;

/* The end and beginning of the the text document. */
@property (nonatomic, readonly) UITextPosition *beginningOfDocument;
@property (nonatomic, readonly) UITextPosition *endOfDocument;

/* Methods for creating ranges and positions. */
- (nullable UITextRange *)textRangeFromPosition:(UITextPosition *)fromPosition toPosition:(UITextPosition *)toPosition;
- (nullable UITextPosition *)positionFromPosition:(UITextPosition *)position offset:(NSInteger)offset;
- (nullable UITextPosition *)positionFromPosition:(UITextPosition *)position inDirection:(UITextLayoutDirection)direction offset:(NSInteger)offset;

/* Simple evaluation of positions */
- (NSComparisonResult)comparePosition:(UITextPosition *)position toPosition:(UITextPosition *)other;
- (NSInteger)offsetFromPosition:(UITextPosition *)from toPosition:(UITextPosition *)toPosition;

/* A system-provied input delegate is assigned when the system is interested in input changes. */
@property (nullable, nonatomic, weak) id <UITextInputDelegate> inputDelegate;

/* A tokenizer must be provided to inform the text input system about text units of varying granularity. */
@property (nonatomic, readonly) id <UITextInputTokenizer> tokenizer;

/* Layout questions. */
- (nullable UITextPosition *)positionWithinRange:(UITextRange *)range farthestInDirection:(UITextLayoutDirection)direction;
- (nullable UITextRange *)characterRangeByExtendingPosition:(UITextPosition *)position inDirection:(UITextLayoutDirection)direction;

/* Writing direction */
- (UITextWritingDirection)baseWritingDirectionForPosition:(UITextPosition *)position inDirection:(UITextStorageDirection)direction;
- (void)setBaseWritingDirection:(UITextWritingDirection)writingDirection forRange:(UITextRange *)range;

/* Geometry used to provide, for example, a correction rect. */
- (CGRect)firstRectForRange:(UITextRange *)range;
- (CGRect)caretRectForPosition:(UITextPosition *)position;
- (NSArray *)selectionRectsForRange:(UITextRange *)range NS_AVAILABLE_IOS(6_0);       // Returns an array of UITextSelectionRects

/* Hit testing. */
- (nullable UITextPosition *)closestPositionToPoint:(CGPoint)point;
- (nullable UITextPosition *)closestPositionToPoint:(CGPoint)point withinRange:(UITextRange *)range;
- (nullable UITextRange *)characterRangeAtPoint:(CGPoint)point;

@optional

- (BOOL)shouldChangeTextInRange:(UITextRange *)range replacementText:(NSString *)text NS_AVAILABLE_IOS(6_0);   // return NO to not change text

/* Text styling information can affect, for example, the appearance of a correction rect.
 * Returns a dictionary containing NSAttributedString keys. */
- (nullable NSDictionary<NSString *,id> *)textStylingAtPosition:(UITextPosition *)position inDirection:(UITextStorageDirection)direction;

/* To be implemented if there is not a one-to-one correspondence between text positions within range and character offsets into the associated string. */
- (nullable UITextPosition *)positionWithinRange:(UITextRange *)range atCharacterOffset:(NSInteger)offset;
- (NSInteger)characterOffsetOfPosition:(UITextPosition *)position withinRange:(UITextRange *)range;

/* An affiliated view that provides a coordinate system for all geometric values in this protocol.
 * If unimplmeented, the first view in the responder chain will be selected. */
@property (nonatomic, readonly) __kindof UIView *textInputView;

/* Selection affinity determines whether, for example, the insertion point appears after the last
 * character on a line or before the first character on the following line in cases where text
 * wraps across line boundaries. */
@property (nonatomic) UITextStorageDirection selectionAffinity;

/* This is an optional method for clients that wish to support dictation phrase alternatives. If 
 * they do not implement this method, dictation will just insert the most likely interpretation 
 * of what was spoken via -insertText:.
 * dictationResult is an array of UIDictationPhrases. */
- (void)insertDictationResult:(NSArray<UIDictationPhrase *> *)dictationResult;

/* These are optional methods for clients that wish to know when there are pending dictation results. */
- (void)dictationRecordingDidEnd;
- (void)dictationRecognitionFailed;

/* The following three optional methods are for clients that wish to support a placeholder for 
 * pending dictation results. -insertDictationPlaceholder must return a reference to the 
 * placeholder. This reference will be used to identify the placeholder by the other methods
 * (there may be more than one placeholder). */
#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly) id insertDictationResultPlaceholder;
#else
- (id)insertDictationResultPlaceholder;
#endif
- (CGRect)frameForDictationResultPlaceholder:(id)placeholder;
/* willInsertResult will be NO if the recognition failed. */
- (void)removeDictationResultPlaceholder:(id)placeholder willInsertResult:(BOOL)willInsertResult;

/* The following three optional methods are for clients that wish to display a floating cursor to
 * guide user manipulation of the selected text range via the system-provided keyboard. If a client
 * does not implement these methods, user feedback will be limited to the outcome after setting the
 * selected text range using positions resulting from hit testing. */
- (void)beginFloatingCursorAtPoint:(CGPoint)point NS_AVAILABLE_IOS(9_0);
- (void)updateFloatingCursorAtPoint:(CGPoint)point NS_AVAILABLE_IOS(9_0);
- (void)endFloatingCursor NS_AVAILABLE_IOS(9_0);

@end

//---------------------------------------------------------------------------------------------------

/* UITextInput keys to style dictionaries are deprecated. Use NSAttributedString keys instead, such as NSFontAttribute, etc. */
UIKIT_EXTERN NSString *const UITextInputTextBackgroundColorKey NS_DEPRECATED_IOS(3_2, 8_0, "Use NSBackgroundColorAttributeName instead") __TVOS_PROHIBITED; // Key to a UIColor
UIKIT_EXTERN NSString *const UITextInputTextColorKey           NS_DEPRECATED_IOS(3_2, 8_0, "Use NSForegroundColorAttributeName instead") __TVOS_PROHIBITED; // Key to a UIColor
UIKIT_EXTERN NSString *const UITextInputTextFontKey            NS_DEPRECATED_IOS(3_2, 8_0, "Use NSFontAttributeName instead") __TVOS_PROHIBITED; // Key to a UIFont

/* To accommodate text entry in documents that contain nested elements, or in which supplying and
 * evaluating characters at indices is an expensive proposition, a position within a text input
 * document is represented as an object, not an integer.  UITextRange and UITextPosition are abstract
 * classes provided to be subclassed when adopting UITextInput */
NS_CLASS_AVAILABLE_IOS(3_2) @interface UITextPosition : NSObject

@end

NS_CLASS_AVAILABLE_IOS(3_2) @interface UITextRange : NSObject

@property (nonatomic, readonly, getter=isEmpty) BOOL empty;     //  Whether the range is zero-length.
@property (nonatomic, readonly) UITextPosition *start;
@property (nonatomic, readonly) UITextPosition *end;

@end

/* UITextSelectionRect defines an annotated selection rect used by the system to
 * offer rich text interaction experience.  It also serves as an abstract class
 * provided to be subclassed when adopting UITextInput */
NS_CLASS_AVAILABLE_IOS(6_0) @interface UITextSelectionRect : NSObject

@property (nonatomic, readonly) CGRect rect;
@property (nonatomic, readonly) UITextWritingDirection writingDirection;
@property (nonatomic, readonly) BOOL containsStart; // Returns YES if the rect contains the start of the selection.
@property (nonatomic, readonly) BOOL containsEnd; // Returns YES if the rect contains the end of the selection.
@property (nonatomic, readonly) BOOL isVertical; // Returns YES if the rect is for vertically oriented text.

@end

/* The input delegate must be notified of changes to the selection and text. */
@protocol UITextInputDelegate <NSObject>

- (void)selectionWillChange:(nullable id <UITextInput>)textInput;
- (void)selectionDidChange:(nullable id <UITextInput>)textInput;
- (void)textWillChange:(nullable id <UITextInput>)textInput;
- (void)textDidChange:(nullable id <UITextInput>)textInput;

@end


/* A tokenizer allows the text input system to evaluate text units of varying granularity. */
@protocol UITextInputTokenizer <NSObject>

@required

- (nullable UITextRange *)rangeEnclosingPosition:(UITextPosition *)position withGranularity:(UITextGranularity)granularity inDirection:(UITextDirection)direction;   // Returns range of the enclosing text unit of the given granularity, or nil if there is no such enclosing unit.  Whether a boundary position is enclosed depends on the given direction, using the same rule as isPosition:withinTextUnit:inDirection:
- (BOOL)isPosition:(UITextPosition *)position atBoundary:(UITextGranularity)granularity inDirection:(UITextDirection)direction;                             // Returns YES only if a position is at a boundary of a text unit of the specified granularity in the particular direction.
- (nullable UITextPosition *)positionFromPosition:(UITextPosition *)position toBoundary:(UITextGranularity)granularity inDirection:(UITextDirection)direction;   // Returns the next boundary position of a text unit of the given granularity in the given direction, or nil if there is no such position.
- (BOOL)isPosition:(UITextPosition *)position withinTextUnit:(UITextGranularity)granularity inDirection:(UITextDirection)direction;                         // Returns YES if position is within a text unit of the given granularity.  If the position is at a boundary, returns YES only if the boundary is part of the text unit in the given direction.

@end


/* A recommended base implementation of the tokenizer protocol. Subclasses are responsible
 * for handling directions and granularities affected by layout.*/
NS_CLASS_AVAILABLE_IOS(3_2) @interface UITextInputStringTokenizer : NSObject <UITextInputTokenizer> 

- (instancetype)initWithTextInput:(UIResponder <UITextInput> *)textInput;

@end

/* The UITextInputMode class should not be subclassed. It is to allow other in-app functionality to adapt 
 * based on the keyboard language. Different UITextInputMode objects may have the same primaryLanguage. */
NS_CLASS_AVAILABLE_IOS(4_2) @interface UITextInputMode : NSObject <NSSecureCoding>

@property (nullable, nonatomic, readonly, strong) NSString *primaryLanguage; // The primary language, if any, of the input mode.  A BCP 47 language identifier such as en-US

// To query the UITextInputMode, refer to the UIResponder method -textInputMode.
+ (nullable UITextInputMode *)currentInputMode NS_DEPRECATED_IOS(4_2, 7_0)  __TVOS_PROHIBITED; // The current input mode.  Nil if unset.
#if UIKIT_DEFINE_AS_PROPERTIES
@property(class, nonatomic, readonly) NSArray<UITextInputMode *> *activeInputModes; // The active input modes.
#else
+ (NSArray<UITextInputMode *> *)activeInputModes; // The active input modes.
#endif

@end

UIKIT_EXTERN NSNotificationName const UITextInputCurrentInputModeDidChangeNotification NS_AVAILABLE_IOS(4_2);

NS_ASSUME_NONNULL_END
