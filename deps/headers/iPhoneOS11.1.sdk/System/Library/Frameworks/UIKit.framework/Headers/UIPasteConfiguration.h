//
//  UIPasteConfiguration.h
//  UIKit
//
//  Copyright © 2007-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN


UIKIT_EXTERN API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, tvos)
@interface UIPasteConfiguration : NSObject <NSSecureCoding, NSCopying>

@property (nonatomic, copy) NSArray<NSString *> *acceptableTypeIdentifiers;

- (instancetype)init NS_DESIGNATED_INITIALIZER;

- (instancetype)initWithAcceptableTypeIdentifiers:(NSArray<NSString *> *)acceptableTypeIdentifiers;
- (void)addAcceptableTypeIdentifiers:(NSArray<NSString *> *)acceptableTypeIdentifiers;

// Uses the readableTypeIdentifiersForItemProvider class property to get acceptable types.
- (instancetype)initWithTypeIdentifiersForAcceptingClass:(Class<NSItemProviderReading>)aClass;
- (void)addTypeIdentifiersForAcceptingClass:(Class<NSItemProviderReading>)aClass;

@end

NS_ASSUME_NONNULL_END
