//
//  INTaskStatusResolutionResult.h
//  Intents
//
//  Copyright (c) 2016-2017 Apple Inc. All rights reserved.
//

#import <Intents/INIntentResolutionResult.h>

#import <Intents/INTaskStatus.h>

NS_ASSUME_NONNULL_BEGIN

API_AVAILABLE(ios(11.0), watchos(4.0))
API_UNAVAILABLE(macosx)
@interface INTaskStatusResolutionResult : INIntentResolutionResult

// This resolution result is for when the app extension wants to tell Siri to proceed, with a given INTaskStatus. The resolvedValue can be different than the original INTaskStatus. This allows app extensions to apply business logic constraints.
// Use +notRequired to continue with a 'nil' value.
+ (instancetype)successWithResolvedTaskStatus:(INTaskStatus)resolvedTaskStatus NS_SWIFT_NAME(success(with:));

+ (instancetype)successWithResolvedValue:(INTaskStatus)resolvedValue NS_SWIFT_UNAVAILABLE("Please use 'success(with:)' instead.") API_DEPRECATED_WITH_REPLACEMENT("+successWithResolvedTaskStatus:", ios(11.0, 11.0), watchos(4.0, 4.0));

// This resolution result is to ask Siri to confirm if this is the value with which the user wants to continue.
+ (instancetype)confirmationRequiredWithTaskStatusToConfirm:(INTaskStatus)taskStatusToConfirm NS_SWIFT_NAME(confirmationRequired(with:));

+ (instancetype)confirmationRequiredWithValueToConfirm:(INTaskStatus)valueToConfirm NS_SWIFT_UNAVAILABLE("Please use 'confirmationRequired(with:)' instead.") API_DEPRECATED_WITH_REPLACEMENT("+confirmationRequiredWithTaskStatusToConfirm:", ios(11.0, 11.0), watchos(4.0, 4.0));

@end

NS_ASSUME_NONNULL_END
