//
//  WKInterfaceController.h
//  WatchKit
//
//  Copyright (c) 2014-2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <WatchKit/WKDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class WKAlertAction;
@class WKInterfaceTable;
@class WKInterfacePicker;
@class WKCrownSequencer;
@class WKInterfaceObject;
@class UIImage;
@class UILocalNotification;
@class PKPass;
@class UNNotification;

typedef NS_ENUM(NSInteger, WKUserNotificationInterfaceType)  {
    WKUserNotificationInterfaceTypeDefault,
    WKUserNotificationInterfaceTypeCustom,
} NS_ENUM_AVAILABLE_IOS(8_2);

typedef NS_ENUM(NSInteger, WKMenuItemIcon)  {
    WKMenuItemIconAccept,       // checkmark
    WKMenuItemIconAdd,          // '+'
    WKMenuItemIconBlock,        // circle w/ slash
    WKMenuItemIconDecline,      // 'x'
    WKMenuItemIconInfo,         // 'i'
    WKMenuItemIconMaybe,        // '?'
    WKMenuItemIconMore,         // '...'
    WKMenuItemIconMute,         // speaker w/ slash
    WKMenuItemIconPause,        // pause button
    WKMenuItemIconPlay,         // play button
    WKMenuItemIconRepeat,       // looping arrows
    WKMenuItemIconResume,       // circular arrow
    WKMenuItemIconShare,        // share icon
    WKMenuItemIconShuffle,      // swapped arrows
    WKMenuItemIconSpeaker,      // speaker icon
    WKMenuItemIconTrash,        // trash icon
} NS_ENUM_AVAILABLE_IOS(8_2);

typedef NS_ENUM(NSInteger, WKTextInputMode)  {
    WKTextInputModePlain,		// text (no emoji) from dictation + suggestions
    WKTextInputModeAllowEmoji, 		// text plus non-animated emoji from dictation + suggestions
    WKTextInputModeAllowAnimatedEmoji,	// all text, animated emoji (GIF data)
};

typedef NS_ENUM(NSInteger, WKAlertControllerStyle) {
    WKAlertControllerStyleAlert,
    WKAlertControllerStyleSideBySideButtonsAlert,
    WKAlertControllerStyleActionSheet,
} WK_AVAILABLE_WATCHOS_ONLY(2.0);

typedef NS_ENUM(NSInteger, WKPageOrientation) {
    WKPageOrientationHorizontal,
    WKPageOrientationVertical,
} WK_AVAILABLE_WATCHOS_ONLY(4.0);

typedef NS_ENUM(NSInteger, WKInterfaceScrollPosition) {
    WKInterfaceScrollPositionTop,
    WKInterfaceScrollPositionCenteredVertically,
    WKInterfaceScrollPositionBottom
} WK_AVAILABLE_WATCHOS_ONLY(4.0);


typedef NS_ENUM(NSInteger, WKVideoGravity)  {
	WKVideoGravityResizeAspect,
	WKVideoGravityResizeAspectFill,
	WKVideoGravityResize
} WK_AVAILABLE_WATCHOS_ONLY(2.0);

/*
 The following presets can be specified to indicate the desired output sample rate. The resulting bit rate depends on the preset and the audio format. The audio file type is inferred from the output URL extension. The audio format is inferred from the audio file type. Supported file types include .wav, .mp4, and .m4a. When the URL extension is .wav, the audio format is LPCM. It is AAC for all other cases.
 */
typedef NS_ENUM(NSInteger, WKAudioRecorderPreset) {
	WKAudioRecorderPresetNarrowBandSpeech,	// @8kHz, LPCM 128kbps, AAC 24kbps
	WKAudioRecorderPresetWideBandSpeech,	// @16kHz, LPCM 256kbps, AAC 32kbps
	WKAudioRecorderPresetHighQualityAudio	// @44.1kHz, LPCM 705.6kbps, AAC 96kbps
} WK_AVAILABLE_WATCHOS_ONLY(2.0);

WK_CLASS_AVAILABLE_IOS(8_2)
@interface WKInterfaceController : NSObject

- (instancetype)init NS_DESIGNATED_INITIALIZER;
- (void)awakeWithContext:(nullable id)context;   // context from controller that did push or modal presentation. default does nothing

@property (nonatomic, readonly) CGRect contentFrame;
@property (nonatomic, strong, readonly) WKCrownSequencer *crownSequencer;

- (void)willActivate;      // Called when watch interface is active and able to be updated. Can be called when interface is not visible.
- (void)didDeactivate;     // Called when watch interface is no longer active and cannot be updated.

- (void)didAppear WK_AVAILABLE_WATCHOS_ONLY(2.0);  // Called when watch interface is visible to user
- (void)willDisappear WK_AVAILABLE_WATCHOS_ONLY(2.0); // Called when watch interface is about to no longer be visible

- (void)pickerDidFocus:(WKInterfacePicker *)picker WK_AVAILABLE_WATCHOS_ONLY(2.0);
- (void)pickerDidResignFocus:(WKInterfacePicker *)picker WK_AVAILABLE_WATCHOS_ONLY(2.0);
- (void)pickerDidSettle:(WKInterfacePicker *)picker WK_AVAILABLE_WATCHOS_ONLY(2.0);

- (void)table:(WKInterfaceTable *)table didSelectRowAtIndex:(NSInteger)rowIndex;  // row selection if controller has WKInterfaceTable property
- (void)handleActionWithIdentifier:(nullable NSString *)identifier forNotification:(UNNotification *)notification WK_AVAILABLE_IOS_ONLY(10.0); // when the app is launched from a notification. If launched from app icon in notification UI, identifier will be empty
- (void)handleUserActivity:(nullable NSDictionary *)userInfo WK_DEPRECATED_WATCHOS(2.0, 4.0, "use WKExtensionDelegate's handleUserActivity:"); // called on root controller(s) with user info

- (void)setTitle:(nullable NSString *)title;        // title of controller. displayed when controller active

- (void)pushControllerWithName:(NSString *)name context:(nullable id)context;  // context passed to child controller via awakeWithContext:
- (void)popController;
- (void)popToRootController;
- (void)scrollToObject:(WKInterfaceObject *)object atScrollPosition:(WKInterfaceScrollPosition)scrollPosition animated:(BOOL)animated WK_AVAILABLE_WATCHOS_ONLY(4.0);
- (void)interfaceDidScrollToTop WK_AVAILABLE_WATCHOS_ONLY(4.0); // Called when user tapped on status bar for scroll-to-top gesture and scrolling animation finished. May be called immediately if already at top
- (void)interfaceOffsetDidScrollToTop WK_AVAILABLE_WATCHOS_ONLY(4.0); // called when user scrolled to the top of the interface controller and scrolling animation finished
- (void)interfaceOffsetDidScrollToBottom WK_AVAILABLE_WATCHOS_ONLY(4.0); // called when user scrolled to the bottom of the interface controller and scrolling animation finished

+ (void)reloadRootControllersWithNames:(NSArray<NSString*> *)names contexts:(nullable NSArray *)contexts WK_DEPRECATED_WATCHOS(2.0, 4.0, "use reloadRootPageControllersWithNames:contexts:orientation:pageIndex:");
+ (void)reloadRootPageControllersWithNames:(NSArray<NSString*> *)names contexts:(nullable NSArray *)contexts orientation:(WKPageOrientation)orientation pageIndex:(NSInteger)pageIndex WK_AVAILABLE_WATCHOS_ONLY(4.0);
- (void)becomeCurrentPage;

- (void)presentControllerWithName:(NSString *)name context:(nullable id)context; // modal presentation
- (void)presentControllerWithNames:(NSArray<NSString*> *)names contexts:(nullable NSArray *)contexts; // modal presentation of paged controllers. contexts matched to controllers
- (void)dismissController;

- (void)presentTextInputControllerWithSuggestions:(nullable NSArray<NSString*> *)suggestions allowedInputMode:(WKTextInputMode)inputMode completion:(void(^)(NSArray * __nullable results))completion; // results is nil if cancelled
- (void)presentTextInputControllerWithSuggestionsForLanguage:(NSArray * __nullable (^ __nullable)(NSString *inputLanguage))suggestionsHandler allowedInputMode:(WKTextInputMode)inputMode completion:(void(^)(NSArray * __nullable results))completion; // will never go straight to dictation because allows for switching input language
- (void)dismissTextInputController;

WKI_EXTERN NSString *const UIUserNotificationActionResponseTypedTextKey WK_AVAILABLE_WATCHOS_ONLY(2.0);

WKI_EXTERN NSString *const WKMediaPlayerControllerOptionsAutoplayKey WK_AVAILABLE_WATCHOS_ONLY(2.0);      // NSNumber containing BOOL
WKI_EXTERN NSString *const WKMediaPlayerControllerOptionsStartTimeKey WK_AVAILABLE_WATCHOS_ONLY(2.0);     // NSNumber containing NSTimeInterval
WKI_EXTERN NSString *const WKMediaPlayerControllerOptionsVideoGravityKey WK_AVAILABLE_WATCHOS_ONLY(2.0);  // NSNumber containing WKVideoGravity
WKI_EXTERN NSString *const WKMediaPlayerControllerOptionsLoopsKey WK_AVAILABLE_WATCHOS_ONLY(2.0);         // NSNumber containing BOOL

- (void)presentMediaPlayerControllerWithURL:(NSURL *)URL options:(nullable NSDictionary *)options completion:(void(^)(BOOL didPlayToEnd, NSTimeInterval endTime, NSError * __nullable error))completion WK_AVAILABLE_WATCHOS_ONLY(2.0);
- (void)dismissMediaPlayerController WK_AVAILABLE_WATCHOS_ONLY(2.0);

WKI_EXTERN NSString *const WKAudioRecorderControllerOptionsActionTitleKey WK_AVAILABLE_WATCHOS_ONLY(2.0);           // NSString (default is "Save")
WKI_EXTERN NSString *const WKAudioRecorderControllerOptionsAlwaysShowActionTitleKey WK_AVAILABLE_WATCHOS_ONLY(2.0); // NSNumber containing BOOL (default is NO)
WKI_EXTERN NSString *const WKAudioRecorderControllerOptionsAutorecordKey WK_AVAILABLE_WATCHOS_ONLY(2.0);            // NSNumber containing BOOL (default is YES)
WKI_EXTERN NSString *const WKAudioRecorderControllerOptionsMaximumDurationKey WK_AVAILABLE_WATCHOS_ONLY(2.0);       // NSNumber containing NSTimeInterval

- (void)presentAudioRecorderControllerWithOutputURL:(NSURL *)URL preset:(WKAudioRecorderPreset)preset options:(nullable NSDictionary *)options completion:(void (^)(BOOL didSave, NSError * __nullable error))completion WK_AVAILABLE_WATCHOS_ONLY(2.0);
- (void)dismissAudioRecorderController WK_AVAILABLE_WATCHOS_ONLY(2.0);

- (nullable id)contextForSegueWithIdentifier:(NSString *)segueIdentifier;
- (nullable NSArray *)contextsForSegueWithIdentifier:(NSString *)segueIdentifier;
- (nullable id)contextForSegueWithIdentifier:(NSString *)segueIdentifier inTable:(WKInterfaceTable *)table rowIndex:(NSInteger)rowIndex;
- (nullable NSArray *)contextsForSegueWithIdentifier:(NSString *)segueIdentifier inTable:(WKInterfaceTable *)table rowIndex:(NSInteger)rowIndex;

- (void)animateWithDuration:(NSTimeInterval)duration animations:(void (^)(void))animations WK_AVAILABLE_WATCHOS_ONLY(2.0);

- (void)presentAlertControllerWithTitle:(nullable NSString *)title message:(nullable NSString *)message preferredStyle:(WKAlertControllerStyle)preferredStyle actions:(NSArray <WKAlertAction *>*)actions WK_AVAILABLE_WATCHOS_ONLY(2.0);

- (void)presentAddPassesControllerWithPasses:(NSArray <PKPass *> *)passes completion:(void(^)(void))completion WK_AVAILABLE_WATCHOS_ONLY(2.0);
- (void)dismissAddPassesController WK_AVAILABLE_WATCHOS_ONLY(2.0);

- (void)addMenuItemWithImage:(UIImage *)image title:(NSString *)title action:(
 SEL)action;           // all parameters must be non-nil
- (void)addMenuItemWithImageNamed:(NSString *)imageName title:(NSString *)title action:(SEL)action;
- (void)addMenuItemWithItemIcon:(WKMenuItemIcon)itemIcon title:(NSString *)title action:(SEL)action;
- (void)clearAllMenuItems;

- (void)updateUserActivity:(NSString *)type userInfo:(nullable NSDictionary *)userInfo webpageURL:(nullable NSURL *)webpageURL;  // provide type and info to Handoff. userInfo and webpageUrl are passed to the application receiving the Handoff
- (void)invalidateUserActivity;

+ (BOOL)openParentApplication:(NSDictionary *)userInfo reply:(nullable void(^)(NSDictionary * replyInfo, NSError * __nullable error)) reply WK_AVAILABLE_IOS_ONLY(8.2);    // launches containing iOS application on the phone. userInfo must be non-nil

- (void)beginGlanceUpdates WK_DEPRECATED_WATCHOS(2.0, 4.0, "Glances are no longer supported");
- (void)endGlanceUpdates WK_DEPRECATED_WATCHOS(2.0, 4.0, "Glances are no longer supported");

// deprecated
- (void)handleActionWithIdentifier:(nullable NSString *)identifier forRemoteNotification:(NSDictionary *)remoteNotification WK_DEPRECATED_WATCHOS_IOS(2.0, 3.0, 8.2, 10.0, "use UNUserNotificationCenterDelegate");
- (void)handleActionWithIdentifier:(nullable NSString *)identifier forLocalNotification:(UILocalNotification *)localNotification WK_DEPRECATED_WATCHOS_IOS(2.0, 3.0, 8.2, 10.0, "use UNUserNotificationCenterDelegate");

@end

WK_CLASS_AVAILABLE_IOS(8_2)
@interface WKUserNotificationInterfaceController : WKInterfaceController

- (instancetype)init NS_DESIGNATED_INITIALIZER;

- (void)didReceiveNotification:(UNNotification *)notification withCompletion:(void(^)(WKUserNotificationInterfaceType interface)) completionHandler WK_AVAILABLE_WATCHOS_IOS(3.0, 10.0);

// Subclasses can implement to return an array of suggestions to use as text responses to a notification.
- (nonnull NSArray<NSString *> *)suggestionsForResponseToActionWithIdentifier:(NSString *)identifier forNotification:(UNNotification *)notification inputLanguage:(NSString *)inputLanguage WK_AVAILABLE_WATCHOS_ONLY(3.0);

// deprecated
- (void)didReceiveRemoteNotification:(NSDictionary *)remoteNotification withCompletion:(void(^)(WKUserNotificationInterfaceType interface)) completionHandler WK_DEPRECATED_WATCHOS_IOS(2.0, 3.0, 8.2, 10.0, "use didReceiveNotification:withCompletion:");
- (void)didReceiveLocalNotification:(UILocalNotification *)localNotification withCompletion:(void(^)(WKUserNotificationInterfaceType interface)) completionHandler WK_DEPRECATED_WATCHOS_IOS(2.0, 3.0, 8.2, 10.0, "use didReceiveNotification:withCompletion:");
- (nonnull NSArray<NSString *> *)suggestionsForResponseToActionWithIdentifier:(NSString *)identifier forRemoteNotification:(NSDictionary *)remoteNotification inputLanguage:(NSString *)inputLanguage WK_AVAILABLE_WATCHOS_ONLY(2.0) WK_DEPRECATED_WATCHOS(2.0, 3.0, "use suggestionsForResponseToActionWithIdentifier:forNotification:inputLanguage:");
- (nonnull NSArray<NSString *> *)suggestionsForResponseToActionWithIdentifier:(NSString *)identifier forLocalNotification:(UILocalNotification *)localNotification inputLanguage:(NSString *)inputLanguage WK_AVAILABLE_WATCHOS_ONLY(2.0) WK_DEPRECATED_WATCHOS(2.0, 3.0, "use suggestionsForResponseToActionWithIdentifier:forNotification:inputLanguage:");

@end

NS_ASSUME_NONNULL_END
