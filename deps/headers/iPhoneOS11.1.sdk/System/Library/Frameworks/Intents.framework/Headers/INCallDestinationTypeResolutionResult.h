//
//  INCallDestinationTypeResolutionResult.h
//  Intents
//
//  Copyright (c) 2016-2017 Apple Inc. All rights reserved.
//

#import <Intents/INIntentResolutionResult.h>

#import <Intents/INCallDestinationType.h>

NS_ASSUME_NONNULL_BEGIN

API_AVAILABLE(ios(11.0), watchos(4.0), macosx(10.13))
@interface INCallDestinationTypeResolutionResult : INIntentResolutionResult

// This resolution result is for when the app extension wants to tell Siri to proceed, with a given INCallDestinationType. The resolvedValue can be different than the original INCallDestinationType. This allows app extensions to apply business logic constraints.
// Use +notRequired to continue with a 'nil' value.
+ (instancetype)successWithResolvedCallDestinationType:(INCallDestinationType)resolvedCallDestinationType NS_SWIFT_NAME(success(with:));

+ (instancetype)successWithResolvedValue:(INCallDestinationType)resolvedValue NS_SWIFT_UNAVAILABLE("Please use 'success(with:)' instead.") API_DEPRECATED_WITH_REPLACEMENT("+successWithResolvedCallDestinationType:", ios(10.0, 11.0), watchos(3.2, 4.0), macos(10.12, 10.13));

// This resolution result is to ask Siri to confirm if this is the value with which the user wants to continue.
+ (instancetype)confirmationRequiredWithCallDestinationTypeToConfirm:(INCallDestinationType)callDestinationTypeToConfirm NS_SWIFT_NAME(confirmationRequired(with:));

+ (instancetype)confirmationRequiredWithValueToConfirm:(INCallDestinationType)valueToConfirm NS_SWIFT_UNAVAILABLE("Please use 'confirmationRequired(with:)' instead.") API_DEPRECATED_WITH_REPLACEMENT("+confirmationRequiredWithCallDestinationTypeToConfirm:", ios(10.0, 11.0), watchos(3.2, 4.0), macos(10.12, 10.13));

@end

NS_ASSUME_NONNULL_END
