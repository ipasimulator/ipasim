
//
//  UIAccessibility.h
//  UIKit
//
//  Copyright (c) 2008-2017 Apple Inc. All rights reserved.
//

#import <CoreGraphics/CoreGraphics.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>
#import <UIKit/UIBezierPath.h>

#import <UIKit/UIAccessibilityAdditions.h>
#import <UIKit/UIAccessibilityConstants.h>
#import <UIKit/UIAccessibilityContainer.h>
#import <UIKit/UIAccessibilityCustomAction.h>
#import <UIKit/UIAccessibilityCustomRotor.h>
#import <UIKit/UIAccessibilityElement.h>
#import <UIKit/UIAccessibilityIdentification.h>
#import <UIKit/UIAccessibilityZoom.h>
#import <UIKit/UIGuidedAccessRestrictions.h>
#import <UIKit/UIAccessibilityLocationDescriptor.h>

NS_ASSUME_NONNULL_BEGIN

/*
 UIAccessibility
 
 UIAccessibility is implemented on all standard UIKit views and controls so
 that assistive applications can present them to users with disabilities.
 
 Custom items in a user interface should override aspects of UIAccessibility
 to supply details where the default value is incomplete.
 
 For example, a UIImageView subclass may need to override accessibilityLabel,
 but it does not need to override accessibilityFrame.
 
 A completely custom subclass of UIView might need to override all of the
 UIAccessibility methods except accessibilityFrame.
 */

@interface NSObject (UIAccessibility)

/*
 Return YES if the receiver should be exposed as an accessibility element. 
 default == NO
 default on UIKit controls == YES 
 Setting the property to YES will cause the receiver to be visible to assistive applications. 
 */
@property (nonatomic) BOOL isAccessibilityElement;

/*
 Returns the localized label that represents the element. 
 If the element does not display text (an icon for example), this method
 should return text that best labels the element. For example: "Play" could be used for
 a button that is used to play music. "Play button" should not be used, since there is a trait
 that identifies the control is a button.
 default == nil
 default on UIKit controls == derived from the title
 Setting the property will change the label that is returned to the accessibility client. 
 */
@property (nullable, nonatomic, copy) NSString *accessibilityLabel;

/*
 The underlying attributed version of the accessibility label. Setting this property will change the
 value of the accessibilityLabel property and vice-versa.
 */
@property (nullable, nonatomic, copy) NSAttributedString *accessibilityAttributedLabel API_AVAILABLE(ios(11.0),tvos(11.0));

/*
 Returns a localized string that describes the result of performing an action on the element, when the result is non-obvious.
 The hint should be a brief phrase.
 For example: "Purchases the item." or "Downloads the attachment."
 default == nil
 Setting the property will change the hint that is returned to the accessibility client. 
 */
@property (nullable, nonatomic, copy) NSString *accessibilityHint;

/*
 The underlying attributed version of the accessibility hint. Setting this property will change the
 value of the accessibilityHint property and vice-versa.
 */
@property (nullable, nonatomic, copy) NSAttributedString *accessibilityAttributedHint API_AVAILABLE(ios(11.0),tvos(11.0));

/*
 Returns a localized string that represents the value of the element, such as the value 
 of a slider or the text in a text field. Use only when the label of the element
 differs from a value. For example: A volume slider has a label of "Volume", but a value of "60%".
 default == nil
 default on UIKit controls == values for appropriate controls 
 Setting the property will change the value that is returned to the accessibility client.  
 */
@property (nullable, nonatomic, copy) NSString *accessibilityValue;

/*
 The underlying attributed version of the accessibility value. Setting this property will change the
 value of the accessibilityValue property and vice-versa.
 */
@property (nullable, nonatomic, copy) NSAttributedString *accessibilityAttributedValue API_AVAILABLE(ios(11.0),tvos(11.0));

/*
 Returns a UIAccessibilityTraits mask that is the OR combination of
 all accessibility traits that best characterize the element.
 See UIAccessibilityConstants.h for a list of traits.
 When overriding this method, remember to combine your custom traits
 with [super accessibilityTraits].
 default == UIAccessibilityTraitNone
 default on UIKit controls == traits that best characterize individual controls. 
 Setting the property will change the traits that are returned to the accessibility client. 
 */
@property (nonatomic) UIAccessibilityTraits accessibilityTraits;

/*
 Returns the frame of the element in screen coordinates.
 default == CGRectZero
 default on UIViews == the frame of the view
 Setting the property will change the frame that is returned to the accessibility client. 
 */
@property (nonatomic) CGRect accessibilityFrame;

// The accessibilityFrame is expected to be in screen coordinates.
// To help convert the frame to screen coordinates, use the following method.
// The rect should exist in the view space of the UIView argument.
UIKIT_EXTERN CGRect UIAccessibilityConvertFrameToScreenCoordinates(CGRect rect, UIView *view) NS_AVAILABLE_IOS(7_0);

/*
 Returns the path of the element in screen coordinates.
 default == nil
 Setting the property, or overriding the method, will cause the assistive technology to prefer the path over the accessibility.
 frame when highlighting the element.
 */
@property (nullable, nonatomic, copy) UIBezierPath *accessibilityPath NS_AVAILABLE_IOS(7_0);

// The accessibilityPath is expected to be in screen coordinates.
// To help convert the path to screen coordinates, use the following method.
// The path should exist in the view space of the UIView argument.
UIKIT_EXTERN UIBezierPath *UIAccessibilityConvertPathToScreenCoordinates(UIBezierPath *path, UIView *view) NS_AVAILABLE_IOS(7_0);

/*
 Returns the activation point for an accessible element in screen coordinates.
 default == Mid-point of the accessibilityFrame.
 */
@property (nonatomic) CGPoint accessibilityActivationPoint NS_AVAILABLE_IOS(5_0);

/*
 Returns the language code that the element's label, value and hint should be spoken in. 
 If no language is set, the user's language is used.
 The format for the language code should follow Internet BCP 47 for language tags.
 For example, en-US specifies U.S. English.
 default == nil
 */
@property (nullable, nonatomic, strong) NSString *accessibilityLanguage;

/*
 Marks all the accessible elements contained within as hidden.
 default == NO
 */
@property (nonatomic) BOOL accessibilityElementsHidden NS_AVAILABLE_IOS(5_0);

/*
 Informs whether the receiving view should be considered modal by accessibility. If YES, then 
 elements outside this view will be ignored. Only elements inside this view will be exposed.
 default == NO
 */
@property (nonatomic) BOOL accessibilityViewIsModal NS_AVAILABLE_IOS(5_0);

/*
 Forces children elements to be grouped together regardless of their position on screen.
 For example, your app may show items that are meant to be grouped together in vertical columns. 
 By default, VoiceOver will navigate those items in horizontal rows. If shouldGroupAccessibilityChildren is set on
 a parent view of the items in the vertical column, VoiceOver will navigate the order correctly.
 default == NO
 */
@property (nonatomic) BOOL shouldGroupAccessibilityChildren NS_AVAILABLE_IOS(6_0);

/*
 Some assistive technologies allow the user to select a parent view or container to navigate its elements.
 This property allows an app to specify whether that behavior should apply to the receiver.
 Currently, this property only affects Switch Control, not VoiceOver or other assistive technologies.
 See UIAccessibilityConstants.h for the list of supported values.
 default == UIAccessibilityNavigationStyleAutomatic
 */
@property (nonatomic) UIAccessibilityNavigationStyle accessibilityNavigationStyle NS_AVAILABLE_IOS(8_0);

/*
 The elements considered to be the headers for this element. May be set on an instance of
 UIAccessibilityElement, a View or a View Controller. The accessibility container chain,
 and associated view controllers where appropriate, will be consulted.
 To avoid retain cycles, a weak copy of the elements will be held.
 */
@property(nullable, nonatomic, copy) NSArray *accessibilityHeaderElements UIKIT_AVAILABLE_TVOS_ONLY(9_0);

@end



/*
 UIAccessibilityFocus
 
 Assistive technologies, like VoiceOver, maintain a virtual focus on an element
 that allows the user to inspect an element without activating it.
 */
@interface NSObject (UIAccessibilityFocus)

// Override the following methods to know when an assistive technology has set or unset its virtual focus on the element. 
- (void)accessibilityElementDidBecomeFocused NS_AVAILABLE_IOS(4_0);
- (void)accessibilityElementDidLoseFocus NS_AVAILABLE_IOS(4_0);

// Returns whether an assistive technology is focused on the element.
- (BOOL)accessibilityElementIsFocused NS_AVAILABLE_IOS(4_0);

// Returns a set of identifier keys indicating which technology is focused on this object
- (nullable NSSet<NSString *> *)accessibilityAssistiveTechnologyFocusedIdentifiers NS_AVAILABLE_IOS(9_0);

// Returns the element that is currently focused by an assistive technology.
// default = nil.
// Pass in a specific identifier (e.g. UIAccessibilityNotificationVoiceOverIdentifier) in order to choose the focused element for a specific product.
// If no argument is used, the function will returned the element that was most recently focused.
UIKIT_EXTERN __nullable id UIAccessibilityFocusedElement(NSString * __nullable assistiveTechnologyIdentifier) NS_AVAILABLE_IOS(9_0);

@end

/*
 UIAccessibilityAction

 An element should implement methods in this category if it supports the action.
 */
@interface NSObject (UIAccessibilityAction)

/*
 Implement accessibilityActivate on an element in order to handle the default action.
 For example, if a native control requires a swipe gesture, you may implement this method so that a
 VoiceOver user will perform a double-tap to activate the item.
 If your implementation successfully handles activate, return YES, otherwise return NO.
 default == NO
 */
- (BOOL)accessibilityActivate NS_AVAILABLE_IOS(7_0);

/* 
 If an element has the UIAccessibilityTraitAdjustable trait, it must also implement
 the following methods. Incrementing will adjust the element so that it increases its content,
 while decrementing decreases its content. For example, accessibilityIncrement will increase the value
 of a UISlider, and accessibilityDecrement will decrease the value.
 */   
- (void)accessibilityIncrement NS_AVAILABLE_IOS(4_0);
- (void)accessibilityDecrement NS_AVAILABLE_IOS(4_0);

/*
 If the user interface requires a scrolling action (e.g. turning the page of a book), a view in the view 
 hierarchy should implement the following method. The return result indicates whether the action 
 succeeded for that direction. If the action failed, the method will be called on a view higher 
 in the hierarchy. If the action succeeds, UIAccessibilityPageScrolledNotification must be posted after
 the scrolling completes.
 default == NO
 */
typedef NS_ENUM(NSInteger, UIAccessibilityScrollDirection) {
    UIAccessibilityScrollDirectionRight = 1,
    UIAccessibilityScrollDirectionLeft,
    UIAccessibilityScrollDirectionUp,
    UIAccessibilityScrollDirectionDown,
    UIAccessibilityScrollDirectionNext NS_ENUM_AVAILABLE_IOS(5_0),
    UIAccessibilityScrollDirectionPrevious NS_ENUM_AVAILABLE_IOS(5_0),
};

- (BOOL)accessibilityScroll:(UIAccessibilityScrollDirection)direction NS_AVAILABLE_IOS(4_2);

/* 
 Implement accessibilityPerformEscape on an element or containing view to exit a modal or hierarchical interface view.
 For example, UIPopoverController implements accessibilityPerformEscape on it's root view, so that when
 called (as a result of a VoiceOver user action), it dismisses the popover.
 If your implementation successfully dismisses the current UI, return YES, otherwise return NO.
 default == NO
 */
- (BOOL)accessibilityPerformEscape NS_AVAILABLE_IOS(5_0);

/* 
 Implement accessibilityPerformMagicTap on an element, or the application, in order to provide a context-sensitive action.
 For example, a music player can implement this to start and stop playback, or a recording app could start and stop recording.
 Return YES to indicate that the action was handled.
 default == NO
 */
- (BOOL)accessibilityPerformMagicTap NS_AVAILABLE_IOS(6_0);

/*
 Return an array of UIAccessibilityCustomAction objects to make custom actions for an element accessible to an assistive technology.
 For example, a photo app might have a view that deletes its corresponding photo in response to a flick gesture.
 If the view returns a delete action from this property, VoiceOver and Switch Control users will be able to delete photos without performing the flick gesture.
 default == nil
 */
@property (nullable, nonatomic, strong) NSArray <UIAccessibilityCustomAction *> *accessibilityCustomActions NS_AVAILABLE_IOS(8_0);
@end

/* 
 UIAccessibilityReadingContent
 
 Implemented on an element that represents content meant to be read, like a book or periodical. 
 Use in conjuction with UIAccessibilityTraitCausesPageTurn to provide a continuous reading experience with VoiceOver.
 */
@protocol UIAccessibilityReadingContent
@required

// Returns the line number given a point in the view's coordinate space.
- (NSInteger)accessibilityLineNumberForPoint:(CGPoint)point NS_AVAILABLE_IOS(5_0);

// Returns the content associated with a line number as a string.
- (nullable NSString *)accessibilityContentForLineNumber:(NSInteger)lineNumber NS_AVAILABLE_IOS(5_0);

// Returns the on-screen rectangle for a line number.
- (CGRect)accessibilityFrameForLineNumber:(NSInteger)lineNumber NS_AVAILABLE_IOS(5_0);

// Returns a string representing the text displayed on the current page.
- (nullable NSString *)accessibilityPageContent NS_AVAILABLE_IOS(5_0);

@optional
// If an object adopting this protocol responds to these methods, the system will try sending them before sending the non-attributed versions.
- (nullable NSAttributedString *)accessibilityAttributedContentForLineNumber:(NSInteger)lineNumber API_AVAILABLE(ios(11.0), tvos(11.0));
- (nullable NSAttributedString *)accessibilityAttributedPageContent API_AVAILABLE(ios(11.0), tvos(11.0));

@end

@interface NSObject(UIAccessibilityDragging)

/* By default, if an accessible view or its subtree has drag and/or drop interactions, they will be
 * automatically exposed by assistive technologies. However, if there is more than one such
 * interaction, each drag or drop should have a name to disambiguate it and give a good user
 * experience. Also, there may be situations in which you want to expose drags or drops from an
 * element, and those interactions are installed on views that are not part of that element's view
 * hierarchy subtree.
 *
 * This is trivially the case when the element is not a view at all, but an instance of
 * UIAccessibilityElement.
 *
 * Another example is when a container view maintains interactions that are logically
 * associated with subviews. For instance, UITableView has associated drag interactions that allow
 * for dragging its rows; to make the rows draggable by assistive technologies, UITableViewCell has
 * drag descriptors that describe where in the table view to start a drag to activate dragging of
 * the cell.
 * (Note that this implementation detail is noted here for expository purposes only and may change
 * at any time without warning.)
 *
 * Properties defined here allow you to fine-tune how drags and drops are exposed to assistive
 * technologies. Both of their getter methods can be overridden to provide information on-demand.
 * For each location descriptor, the associated view should be the UIView with the appropriate
 * UIInteraction object for that drag or drop.
 *
 * `accessibilityDragSourceDescriptors` is an array of UIAccessibilityLocationDescriptor
 * objects and is used to define and describe what drags are available from an element.
 *
 * `accessibilityDropPointDescriptors` is similarly an array of
 * UIAccessibilityLocationDescriptor objects and is used to define and describe where
 * drops are possible on this element.
 *
 * To restore the default automatic behavior for these properties, assign (or return) the default
 * value of nil. Note that nil does not describe the same behavior as the empty array, which
 * specifies that there are no relevant interactions for this element.
 *
 */
@property (nullable, nonatomic, copy) NSArray<UIAccessibilityLocationDescriptor *> *accessibilityDragSourceDescriptors API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, tvos);

@property (nullable, nonatomic, copy) NSArray<UIAccessibilityLocationDescriptor *> *accessibilityDropPointDescriptors API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, tvos);


@end

/*
 UIAccessibilityPostNotification
 
 This function posts a notification to assistive applications.
 Some notifications specify a required or optional argument.
 Pass nil for the argument if the notification does not specify otherwise. 
 See UIAccessibilityConstants.h for a list of notifications.
 */
UIKIT_EXTERN void UIAccessibilityPostNotification(UIAccessibilityNotifications notification, __nullable id argument);

/* 
 Assistive Technology
 
 Use UIAccessibilityIsVoiceOverRunning() to determine if VoiceOver is running.
 Listen for UIAccessibilityVoiceOverStatusDidChangeNotification to know when VoiceOver starts or stops.
 */
UIKIT_EXTERN BOOL UIAccessibilityIsVoiceOverRunning(void) NS_AVAILABLE_IOS(4_0);
UIKIT_EXTERN NSString *const UIAccessibilityVoiceOverStatusChanged API_DEPRECATED_WITH_REPLACEMENT("UIAccessibilityVoiceOverStatusDidChangeNotification", ios(4.0, 11.0), tvos(9.0, 11.0));
UIKIT_EXTERN NSNotificationName const UIAccessibilityVoiceOverStatusDidChangeNotification API_AVAILABLE(ios(11.0), tvos(11.0));

// Returns whether system audio is mixed down from stereo to mono.
UIKIT_EXTERN BOOL UIAccessibilityIsMonoAudioEnabled(void) NS_AVAILABLE_IOS(5_0);
UIKIT_EXTERN NSString *const UIAccessibilityMonoAudioStatusDidChangeNotification NS_AVAILABLE_IOS(5_0);

// Returns whether the system preference for closed captioning is enabled.
UIKIT_EXTERN BOOL UIAccessibilityIsClosedCaptioningEnabled(void) NS_AVAILABLE_IOS(5_0);
UIKIT_EXTERN NSString *const UIAccessibilityClosedCaptioningStatusDidChangeNotification NS_AVAILABLE_IOS(5_0);

// Returns whether the system preference for invert colors is enabled.
UIKIT_EXTERN BOOL UIAccessibilityIsInvertColorsEnabled(void) NS_AVAILABLE_IOS(6_0);
UIKIT_EXTERN NSString *const UIAccessibilityInvertColorsStatusDidChangeNotification NS_AVAILABLE_IOS(6_0);

// Returns whether the app is running under Guided Access mode.
UIKIT_EXTERN BOOL UIAccessibilityIsGuidedAccessEnabled(void) NS_AVAILABLE_IOS(6_0);
UIKIT_EXTERN NSString *const UIAccessibilityGuidedAccessStatusDidChangeNotification NS_AVAILABLE_IOS(6_0);

// Returns whether the system preference for bold text is enabled
UIKIT_EXTERN BOOL UIAccessibilityIsBoldTextEnabled(void) NS_AVAILABLE_IOS(8_0);
UIKIT_EXTERN NSString *const UIAccessibilityBoldTextStatusDidChangeNotification NS_AVAILABLE_IOS(8_0);

// Returns whether the system preference for grayscale is enabled
UIKIT_EXTERN BOOL UIAccessibilityIsGrayscaleEnabled(void) NS_AVAILABLE_IOS(8_0);
UIKIT_EXTERN NSString *const UIAccessibilityGrayscaleStatusDidChangeNotification NS_AVAILABLE_IOS(8_0);

// Returns whether the system preference for reduce transparency is enabled
UIKIT_EXTERN BOOL UIAccessibilityIsReduceTransparencyEnabled(void) NS_AVAILABLE_IOS(8_0);
UIKIT_EXTERN NSString *const UIAccessibilityReduceTransparencyStatusDidChangeNotification NS_AVAILABLE_IOS(8_0);

// Returns whether the system preference for reduce motion is enabled
UIKIT_EXTERN BOOL UIAccessibilityIsReduceMotionEnabled(void) NS_AVAILABLE_IOS(8_0);
UIKIT_EXTERN NSString *const UIAccessibilityReduceMotionStatusDidChangeNotification NS_AVAILABLE_IOS(8_0);

// Returns whether the system preference for darker colors is enabled
UIKIT_EXTERN BOOL UIAccessibilityDarkerSystemColorsEnabled(void) NS_AVAILABLE_IOS(8_0);
UIKIT_EXTERN NSString *const UIAccessibilityDarkerSystemColorsStatusDidChangeNotification NS_AVAILABLE_IOS(8_0);

/*
 Use UIAccessibilityIsSwitchControlRunning() to determine if Switch Control is running.
 Listen for UIAccessibilitySwitchControlStatusDidChangeNotification to know when Switch Control starts or stops.
*/
UIKIT_EXTERN BOOL UIAccessibilityIsSwitchControlRunning(void) NS_AVAILABLE_IOS(8_0);
UIKIT_EXTERN NSString *const UIAccessibilitySwitchControlStatusDidChangeNotification NS_AVAILABLE_IOS(8_0);

// Returns whether the system preference for Speak Selection is enabled
UIKIT_EXTERN BOOL UIAccessibilityIsSpeakSelectionEnabled(void) NS_AVAILABLE_IOS(8_0);
UIKIT_EXTERN NSString *const UIAccessibilitySpeakSelectionStatusDidChangeNotification NS_AVAILABLE_IOS(8_0);

// Returns whether the system preference for Speak Screen is enabled
UIKIT_EXTERN BOOL UIAccessibilityIsSpeakScreenEnabled(void) NS_AVAILABLE_IOS(8_0);
UIKIT_EXTERN NSString *const UIAccessibilitySpeakScreenStatusDidChangeNotification NS_AVAILABLE_IOS(8_0);

// Returns whether the system preference for Shake to Undo is enabled
UIKIT_EXTERN BOOL UIAccessibilityIsShakeToUndoEnabled(void) NS_AVAILABLE_IOS(9_0);
UIKIT_EXTERN NSString *const UIAccessibilityShakeToUndoDidChangeNotification NS_AVAILABLE_IOS(9_0);

// Returns whether the system preference for AssistiveTouch is enabled.
// This always returns false if Guided Access is not enabled.
UIKIT_EXTERN BOOL UIAccessibilityIsAssistiveTouchRunning(void) NS_AVAILABLE_IOS(10_0);
UIKIT_EXTERN NSString *const UIAccessibilityAssistiveTouchStatusDidChangeNotification NS_AVAILABLE_IOS(10_0);

/*
 Use UIAccessibilityRequestGuidedAccessSession() to request this app be locked into or released
 from Single App mode. The request to lock this app into Single App mode will only succeed if the device is Supervised,
 and the app's bundle identifier has been whitelisted using Mobile Device Management. If you successfully request Single
 App mode, it is your responsibility to release the device by balancing this call.
 */
UIKIT_EXTERN void UIAccessibilityRequestGuidedAccessSession(BOOL enable, void(^completionHandler)(BOOL didSucceed)) NS_AVAILABLE_IOS(7_0);

typedef NS_OPTIONS(NSUInteger, UIAccessibilityHearingDeviceEar) {
    UIAccessibilityHearingDeviceEarNone    = 0,
    UIAccessibilityHearingDeviceEarLeft    = 1 << 1,
    UIAccessibilityHearingDeviceEarRight   = 1 << 2,
    UIAccessibilityHearingDeviceEarBoth    = UIAccessibilityHearingDeviceEarLeft | UIAccessibilityHearingDeviceEarRight,
} NS_ENUM_AVAILABLE_IOS(10_0) __TVOS_PROHIBITED;

// Returns the current pairing status of MFi hearing aids
UIKIT_EXTERN UIAccessibilityHearingDeviceEar UIAccessibilityHearingDevicePairedEar(void) NS_AVAILABLE_IOS(10_0) __TVOS_PROHIBITED;
UIKIT_EXTERN NSString *const UIAccessibilityHearingDevicePairedEarDidChangeNotification NS_AVAILABLE_IOS(10_0) __TVOS_PROHIBITED;

NS_ASSUME_NONNULL_END
