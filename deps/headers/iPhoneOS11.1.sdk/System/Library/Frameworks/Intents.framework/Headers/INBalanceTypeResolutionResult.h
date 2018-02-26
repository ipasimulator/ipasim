//
//  INBalanceTypeResolutionResult.h
//  Intents
//
//  Copyright (c) 2016-2017 Apple Inc. All rights reserved.
//

#import <Intents/INIntentResolutionResult.h>

#import <Intents/INBalanceType.h>

NS_ASSUME_NONNULL_BEGIN

API_AVAILABLE(ios(11.0), watchos(4.0))
API_UNAVAILABLE(macosx)
@interface INBalanceTypeResolutionResult : INIntentResolutionResult

// This resolution result is for when the app extension wants to tell Siri to proceed, with a given INBalanceType. The resolvedValue can be different than the original INBalanceType. This allows app extensions to apply business logic constraints.
// Use +notRequired to continue with a 'nil' value.
+ (instancetype)successWithResolvedBalanceType:(INBalanceType)resolvedBalanceType NS_SWIFT_NAME(success(with:));

+ (instancetype)successWithResolvedValue:(INBalanceType)resolvedValue NS_SWIFT_UNAVAILABLE("Please use 'success(with:)' instead.") API_DEPRECATED_WITH_REPLACEMENT("+successWithResolvedBalanceType:", ios(11.0, 11.0), watchos(4.0, 4.0));

// This resolution result is to ask Siri to confirm if this is the value with which the user wants to continue.
+ (instancetype)confirmationRequiredWithBalanceTypeToConfirm:(INBalanceType)balanceTypeToConfirm NS_SWIFT_NAME(confirmationRequired(with:));

+ (instancetype)confirmationRequiredWithValueToConfirm:(INBalanceType)valueToConfirm NS_SWIFT_UNAVAILABLE("Please use 'confirmationRequired(with:)' instead.") API_DEPRECATED_WITH_REPLACEMENT("+confirmationRequiredWithBalanceTypeToConfirm:", ios(11.0, 11.0), watchos(4.0, 4.0));

@end

NS_ASSUME_NONNULL_END
