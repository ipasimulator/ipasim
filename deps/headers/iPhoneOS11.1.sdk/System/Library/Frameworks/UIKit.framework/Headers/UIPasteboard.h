//
//  UIPasteboard.h
//  UIKit
//
//  Copyright (c) 2008-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

#if UIKIT_STRING_ENUMS
typedef NSString * UIPasteboardName NS_EXTENSIBLE_STRING_ENUM;
#else
typedef NSString * UIPasteboardName;
#endif

UIKIT_EXTERN UIPasteboardName const UIPasteboardNameGeneral __TVOS_PROHIBITED __WATCHOS_PROHIBITED;
UIKIT_EXTERN NSString *const UIPasteboardNameFind __TVOS_PROHIBITED __WATCHOS_PROHIBITED NS_DEPRECATED_IOS(3_0, 10_0, "The Find pasteboard is no longer available.");

@class UIColor, UIImage;

NS_CLASS_AVAILABLE_IOS(3_0) __TVOS_PROHIBITED __WATCHOS_PROHIBITED @interface UIPasteboard : NSObject

#if UIKIT_DEFINE_AS_PROPERTIES
@property(class, nonatomic, readonly) UIPasteboard *generalPasteboard;
#else
+ (UIPasteboard *)generalPasteboard;
#endif

+ (nullable UIPasteboard *)pasteboardWithName:(UIPasteboardName)pasteboardName create:(BOOL)create;
+ (UIPasteboard *)pasteboardWithUniqueName;

@property(readonly,nonatomic) UIPasteboardName name;

+ (void)removePasteboardWithName:(UIPasteboardName)pasteboardName;

@property(readonly,getter=isPersistent,nonatomic) BOOL persistent;
- (void)setPersistent:(BOOL)persistent NS_DEPRECATED_IOS(3_0, 10_0, "Do not set persistence on pasteboards. This property is set automatically.");
@property(readonly,nonatomic) NSInteger changeCount;

// Item provider interface

@property (nonatomic, copy) NSArray<__kindof NSItemProvider *> *itemProviders API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, tvos);

- (void)setItemProviders:(NSArray<NSItemProvider *> *)itemProviders localOnly:(BOOL)localOnly expirationDate:(NSDate * _Nullable)expirationDate API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, tvos);

// Automatically creates item providers wrapping the objects passed in.
- (void)setObjects:(NSArray<id<NSItemProviderWriting>> *)objects API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, tvos);
- (void)setObjects:(NSArray<id<NSItemProviderWriting>> *)objects localOnly:(BOOL)localOnly expirationDate:(NSDate * _Nullable)expirationDate API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, tvos);

// First item

#if UIKIT_DEFINE_AS_PROPERTIES
@property(nonatomic, readonly) NSArray<NSString *> * pasteboardTypes;
#else
- (NSArray<NSString *> *)pasteboardTypes;
#endif
- (BOOL)containsPasteboardTypes:(NSArray<NSString *> *)pasteboardTypes;
- (nullable NSData *)dataForPasteboardType:(NSString *)pasteboardType;

- (nullable id)valueForPasteboardType:(NSString *)pasteboardType;

- (void)setValue:(id)value forPasteboardType:(NSString *)pasteboardType;
- (void)setData:(NSData *)data forPasteboardType:(NSString *)pasteboardType;

// Multiple items

@property(readonly,nonatomic) NSInteger numberOfItems;
- (nullable NSArray<NSArray<NSString *> *> *)pasteboardTypesForItemSet:(nullable NSIndexSet*)itemSet;

- (BOOL)containsPasteboardTypes:(NSArray<NSString *> *)pasteboardTypes inItemSet:(nullable NSIndexSet *)itemSet;
- (nullable NSIndexSet *)itemSetWithPasteboardTypes:(NSArray<NSString *> *)pasteboardTypes;
- (nullable NSArray *)valuesForPasteboardType:(NSString *)pasteboardType inItemSet:(nullable NSIndexSet *)itemSet;
- (nullable NSArray *)dataForPasteboardType:(NSString *)pasteboardType inItemSet:(nullable NSIndexSet *)itemSet;

// Direct access

@property(nonatomic,copy) NSArray<NSDictionary<NSString *, id> *> *items;
- (void)addItems:(NSArray<NSDictionary<NSString *, id> *> *)items;

typedef NSString * UIPasteboardOption NS_EXTENSIBLE_STRING_ENUM NS_AVAILABLE_IOS(10_0);

UIKIT_EXTERN UIPasteboardOption const UIPasteboardOptionExpirationDate __TVOS_PROHIBITED __WATCHOS_PROHIBITED NS_AVAILABLE_IOS(10_0) NS_SWIFT_NAME(UIPasteboardOption.expirationDate); // Value: NSDate.
UIKIT_EXTERN UIPasteboardOption const UIPasteboardOptionLocalOnly __TVOS_PROHIBITED __WATCHOS_PROHIBITED NS_AVAILABLE_IOS(10_0) NS_SWIFT_NAME(UIPasteboardOption.localOnly); // Value: NSNumber, boolean.

- (void)setItems:(NSArray<NSDictionary<NSString *, id> *> *)items options:(NSDictionary<UIPasteboardOption, id> *)options NS_AVAILABLE_IOS(10_0);

@property(nullable,nonatomic,copy) NSString *string __TVOS_PROHIBITED __WATCHOS_PROHIBITED;
@property(nullable,nonatomic,copy) NSArray<NSString *> *strings __TVOS_PROHIBITED __WATCHOS_PROHIBITED;

@property(nullable,nonatomic,copy) NSURL *URL __TVOS_PROHIBITED __WATCHOS_PROHIBITED;
@property(nullable,nonatomic,copy) NSArray<NSURL *> *URLs __TVOS_PROHIBITED __WATCHOS_PROHIBITED;

@property(nullable,nonatomic,copy) UIImage *image __TVOS_PROHIBITED __WATCHOS_PROHIBITED;
@property(nullable,nonatomic,copy) NSArray<UIImage *> *images __TVOS_PROHIBITED __WATCHOS_PROHIBITED;

@property(nullable,nonatomic,copy) UIColor *color __TVOS_PROHIBITED __WATCHOS_PROHIBITED;
@property(nullable,nonatomic,copy) NSArray<UIColor *> *colors __TVOS_PROHIBITED __WATCHOS_PROHIBITED;

// Queries

@property (nonatomic, readonly) BOOL hasStrings __TVOS_PROHIBITED __WATCHOS_PROHIBITED NS_AVAILABLE_IOS(10_0);
@property (nonatomic, readonly) BOOL hasURLs __TVOS_PROHIBITED __WATCHOS_PROHIBITED NS_AVAILABLE_IOS(10_0);
@property (nonatomic, readonly) BOOL hasImages __TVOS_PROHIBITED __WATCHOS_PROHIBITED NS_AVAILABLE_IOS(10_0);
@property (nonatomic, readonly) BOOL hasColors __TVOS_PROHIBITED __WATCHOS_PROHIBITED NS_AVAILABLE_IOS(10_0);

@end

// Notification

UIKIT_EXTERN NSNotificationName const UIPasteboardChangedNotification __TVOS_PROHIBITED __WATCHOS_PROHIBITED;
UIKIT_EXTERN NSString *const UIPasteboardChangedTypesAddedKey __TVOS_PROHIBITED __WATCHOS_PROHIBITED;
UIKIT_EXTERN NSString *const UIPasteboardChangedTypesRemovedKey __TVOS_PROHIBITED __WATCHOS_PROHIBITED;

UIKIT_EXTERN NSNotificationName const UIPasteboardRemovedNotification __TVOS_PROHIBITED __WATCHOS_PROHIBITED;

// Types

UIKIT_EXTERN NSArray<NSString *> *UIPasteboardTypeListString __TVOS_PROHIBITED __WATCHOS_PROHIBITED;
UIKIT_EXTERN NSArray<NSString *> *UIPasteboardTypeListURL __TVOS_PROHIBITED __WATCHOS_PROHIBITED;
UIKIT_EXTERN NSArray<NSString *> *UIPasteboardTypeListImage __TVOS_PROHIBITED __WATCHOS_PROHIBITED;
UIKIT_EXTERN NSArray<NSString *> *UIPasteboardTypeListColor __TVOS_PROHIBITED __WATCHOS_PROHIBITED;

// Use the following type in setItems: or setItems:options: to automatically insert appropriate UTIs for supported types.
// Supported types are: NSString, NSURL, UIImage, UIColor, NSAttributedString.
UIKIT_EXTERN NSString * const UIPasteboardTypeAutomatic __TVOS_PROHIBITED __WATCHOS_PROHIBITED NS_AVAILABLE_IOS(10_0);

NS_ASSUME_NONNULL_END
    
