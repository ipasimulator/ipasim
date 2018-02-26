//
//  INDateSearchTypeResolutionResult.h
//  Intents
//
//  Copyright (c) 2016-2017 Apple Inc. All rights reserved.
//

#import <Intents/INIntentResolutionResult.h>

#import <Intents/INDateSearchType.h>

NS_ASSUME_NONNULL_BEGIN

API_AVAILABLE(ios(11.0), watchos(4.0))
API_UNAVAILABLE(macosx)
@interface INDateSearchTypeResolutionResult : INIntentResolutionResult

// This resolution result is for when the app extension wants to tell Siri to proceed, with a given INDateSearchType. The resolvedValue can be different than the original INDateSearchType. This allows app extensions to apply business logic constraints.
// Use +notRequired to continue with a 'nil' value.
+ (instancetype)successWithResolvedDateSearchType:(INDateSearchType)resolvedDateSearchType NS_SWIFT_NAME(success(with:));

+ (instancetype)successWithResolvedValue:(INDateSearchType)resolvedValue NS_SWIFT_UNAVAILABLE("Please use 'success(with:)' instead.") API_DEPRECATED_WITH_REPLACEMENT("+successWithResolvedDateSearchType:", ios(11.0, 11.0), watchos(4.0, 4.0));

// This resolution result is to ask Siri to confirm if this is the value with which the user wants to continue.
+ (instancetype)confirmationRequiredWithDateSearchTypeToConfirm:(INDateSearchType)dateSearchTypeToConfirm NS_SWIFT_NAME(confirmationRequired(with:));

+ (instancetype)confirmationRequiredWithValueToConfirm:(INDateSearchType)valueToConfirm NS_SWIFT_UNAVAILABLE("Please use 'confirmationRequired(with:)' instead.") API_DEPRECATED_WITH_REPLACEMENT("+confirmationRequiredWithDateSearchTypeToConfirm:", ios(11.0, 11.0), watchos(4.0, 4.0));

@end

NS_ASSUME_NONNULL_END
