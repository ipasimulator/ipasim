//
//  INNotebookItemTypeResolutionResult.h
//  Intents
//
//  Copyright (c) 2016-2017 Apple Inc. All rights reserved.
//

#import <Intents/INIntentResolutionResult.h>

#import <Intents/INNotebookItemType.h>

NS_ASSUME_NONNULL_BEGIN

API_AVAILABLE(ios(11.0), watchos(4.0))
API_UNAVAILABLE(macosx)
@interface INNotebookItemTypeResolutionResult : INIntentResolutionResult

// This resolution result is for when the app extension wants to tell Siri to proceed, with a given INNotebookItemType. The resolvedValue can be different than the original INNotebookItemType. This allows app extensions to apply business logic constraints.
// Use +notRequired to continue with a 'nil' value.
+ (instancetype)successWithResolvedNotebookItemType:(INNotebookItemType)resolvedNotebookItemType NS_SWIFT_NAME(success(with:));

+ (instancetype)successWithResolvedValue:(INNotebookItemType)resolvedValue NS_SWIFT_UNAVAILABLE("Please use 'success(with:)' instead.") API_DEPRECATED_WITH_REPLACEMENT("+successWithResolvedNotebookItemType:", ios(11.0, 11.0), watchos(4.0, 4.0));

// This resolution result is to ask Siri to disambiguate between the provided values.
+ (instancetype)disambiguationWithNotebookItemTypesToDisambiguate:(NSArray<NSNumber *> *)notebookItemTypesToDisambiguate NS_REFINED_FOR_SWIFT;

+ (instancetype)disambiguationWithValuesToDisambiguate:(NSArray<NSNumber *> *)valuesToDisambiguate NS_REFINED_FOR_SWIFT API_DEPRECATED_WITH_REPLACEMENT("+disambiguationWithNotebookItemTypesToDisambiguate:", ios(11.0, 11.0), watchos(4.0, 4.0));

// This resolution result is to ask Siri to confirm if this is the value with which the user wants to continue.
+ (instancetype)confirmationRequiredWithNotebookItemTypeToConfirm:(INNotebookItemType)notebookItemTypeToConfirm NS_SWIFT_NAME(confirmationRequired(with:));

+ (instancetype)confirmationRequiredWithValueToConfirm:(INNotebookItemType)valueToConfirm NS_SWIFT_UNAVAILABLE("Please use 'confirmationRequired(with:)' instead.") API_DEPRECATED_WITH_REPLACEMENT("+confirmationRequiredWithNotebookItemTypeToConfirm:", ios(11.0, 11.0), watchos(4.0, 4.0));

@end

NS_ASSUME_NONNULL_END
