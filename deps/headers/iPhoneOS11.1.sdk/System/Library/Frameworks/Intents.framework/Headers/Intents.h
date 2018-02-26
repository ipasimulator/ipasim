//
//  Intents.h
//  Intents
//
//  Copyright (c) 2016-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

//! Project version number for Intents.
FOUNDATION_EXPORT double IntentsVersionNumber;

//! Project version string for Intents.
FOUNDATION_EXPORT const unsigned char IntentsVersionString[];

#ifndef __INTENTS_INDIRECT__
#define __INTENTS_INDIRECT__
#endif

// Base
#import <Intents/INIntent.h>
#import <Intents/INIntentErrors.h>
#import <Intents/INIntentHandlerProviding.h>
#import <Intents/INIntentIdentifiers.h>
#import <Intents/INIntentResponse.h>
#import <Intents/INIntentResolutionResult.h>
#import <Intents/INDomainHandling.h>
#import <Intents/INInteraction.h>
#import <Intents/INSpeakable.h>
#import <Intents/INParameter.h>

// Intents & Intent Responses
#import <Intents/INIntents.h>
#import <Intents/INIntentResponses.h>

// Extension
#import <Intents/INExtension.h>

// Common Types
#import <Intents/INPersonHandle.h>
#import <Intents/INCurrencyAmount.h>
#import <Intents/INDateComponentsRange.h>
#import <Intents/INImage.h>
#import <Intents/INPaymentMethod.h>
#import <Intents/INPaymentMethodType.h>
#import <Intents/INPerson.h>
#import <Intents/INRecurrenceRule.h>
#import <Intents/INSpeakableString.h>
#import <Intents/INPersonHandleLabel.h>
#import <Intents/INPersonRelationship.h>

// Common Resolution Results
#import <Intents/INBooleanResolutionResult.h>
#import <Intents/INCurrencyAmountResolutionResult.h>
#import <Intents/INDateComponentsRangeResolutionResult.h>
#import <Intents/INDoubleResolutionResult.h>
#import <Intents/INIntegerResolutionResult.h>
#import <Intents/INPersonResolutionResult.h>
#import <Intents/INPlacemarkResolutionResult.h>
#import <Intents/INSpeakableStringResolutionResult.h>
#import <Intents/INStringResolutionResult.h>
#import <Intents/INTemperatureResolutionResult.h>
#import <Intents/INDateComponentsResolutionResult.h>
#import <Intents/INRestaurantResolutionResult.h>
#import <Intents/INRestaurantGuestResolutionResult.h>

// Calls Domain
#import <Intents/INCallRecord.h>
#import <Intents/INCallRecordType.h>
#import <Intents/INCallRecordTypeResolutionResult.h>
#import <Intents/INCallDestinationType.h>
#import <Intents/INCallDestinationTypeResolutionResult.h>
#import <Intents/INCallCapability.h>
#import <Intents/INCallCapabilityOptions.h>
#import <Intents/INCallRecordTypeOptionsResolutionResult.h>

// CarPlay & Radio Domains
#import <Intents/INCarAirCirculationMode.h>
#import <Intents/INCarAirCirculationModeResolutionResult.h>
#import <Intents/INCarAudioSource.h>
#import <Intents/INCarAudioSourceResolutionResult.h>
#import <Intents/INCarDefroster.h>
#import <Intents/INCarDefrosterResolutionResult.h>
#import <Intents/INCarSeat.h>
#import <Intents/INCarSeatResolutionResult.h>
#import <Intents/INCarSignalOptions.h>
#import <Intents/INCarSignalOptionsResolutionResult.h>
#import <Intents/INRadioType.h>
#import <Intents/INRadioTypeResolutionResult.h>
#import <Intents/INRelativeReference.h>
#import <Intents/INRelativeReferenceResolutionResult.h>
#import <Intents/INRelativeSetting.h>
#import <Intents/INRelativeSettingResolutionResult.h>

// Messages Domain
#import <Intents/INSendMessageRecipientResolutionResult.h>

#import <Intents/INMessage.h>
#import <Intents/INMessageAttribute.h>
#import <Intents/INMessageAttributeResolutionResult.h>
#import <Intents/INMessageAttributeOptions.h>
#import <Intents/INMessageAttributeOptionsResolutionResult.h>

// Payments Domain
#import <Intents/INAccountTypeResolutionResult.h>
#import <Intents/INBalanceAmount.h>
#import <Intents/INBalanceTypeResolutionResult.h>
#import <Intents/INBillDetails.h>
#import <Intents/INBillPayee.h>
#import <Intents/INBillPayeeResolutionResult.h>
#import <Intents/INBillType.h>
#import <Intents/INPaymentRecord.h>
#import <Intents/INPaymentStatus.h>
#import <Intents/INPaymentAccount.h>
#import <Intents/INPaymentAccountResolutionResult.h>
#import <Intents/INPaymentAmount.h>
#import <Intents/INPaymentAmountResolutionResult.h>
#import <Intents/INBillTypeResolutionResult.h>
#import <Intents/INPaymentStatusResolutionResult.h>
#import <Intents/INSendPaymentCurrencyAmountResolutionResult.h>
#import <Intents/INRequestPaymentCurrencyAmountResolutionResult.h>
#import <Intents/INSendPaymentPayeeResolutionResult.h>
#import <Intents/INRequestPaymentPayerResolutionResult.h>

// Photos Domain
#import <Intents/INPhotoAttributeOptions.h>

// Ridesharing Domain
#import <Intents/INPriceRange.h>
#import <Intents/INRideOption.h>
#import <Intents/INRideStatus.h>
#import <Intents/INRidePhase.h>
#import <Intents/INRideDriver.h>
#import <Intents/INRideVehicle.h>
#import <Intents/INRideFareLineItem.h>
#import <Intents/INRidePartySizeOption.h>
#import <Intents/INRideCompletionStatus.h>
#import <Intents/INRideFeedbackTypeOptions.h>

// Visual Code Domain
#import <Intents/INVisualCodeType.h>
#import <Intents/INVisualCodeTypeResolutionResult.h>

// Workouts Domain
#import <Intents/INWorkoutGoalUnitType.h>
#import <Intents/INWorkoutGoalUnitTypeResolutionResult.h>
#import <Intents/INWorkoutLocationType.h>
#import <Intents/INWorkoutLocationTypeResolutionResult.h>
#import <Intents/INWorkoutNameIdentifier.h>

// Restaurant Booking
#import <Intents/INIntentRestaurantReservation.h>

// User Vocabulary
#import <Intents/INVocabulary.h>

// Utilities
#import <Intents/INSiriAuthorizationStatus.h>
#import <Intents/INPreferences.h>
#import <Intents/CLPlacemark+IntentsAdditions.h>
#import <Intents/NSUserActivity+IntentsAdditions.h>
#import <Intents/INPerson+SiriAdditions.h>

// Notes
#import <Intents/INNoteContent.h>
#import <Intents/INTextNoteContent.h>
#import <Intents/INNote.h>
#import <Intents/INTask.h>
#import <Intents/INTaskList.h>
#import <Intents/INSpatialEventTrigger.h>
#import <Intents/INTemporalEventTrigger.h>
#import <Intents/INDateSearchType.h>
#import <Intents/INLocationSearchType.h>
#import <Intents/INNoteContentType.h>
#import <Intents/INNotebookItemType.h>
#import <Intents/INImageNoteContent.h>
#import <Intents/INSortType.h>

#import <Intents/INDateSearchTypeResolutionResult.h>
#import <Intents/INLocationSearchTypeResolutionResult.h>
#import <Intents/INNoteResolutionResult.h>
#import <Intents/INNoteContentResolutionResult.h>
#import <Intents/INNoteContentTypeResolutionResult.h>
#import <Intents/INNotebookItemTypeResolutionResult.h>
#import <Intents/INTaskResolutionResult.h>
#import <Intents/INTaskListResolutionResult.h>
#import <Intents/INTaskStatusResolutionResult.h>
#import <Intents/INSpatialEventTriggerResolutionResult.h>
#import <Intents/INTemporalEventTriggerResolutionResult.h>

// Deprecated
#import <Intents/INPerson_Deprecated.h>
#import <Intents/INRequestRideIntent_Deprecated.h>
#import <Intents/INRideDriver_Deprecated.h>
#import <Intents/INSaveProfileInCarIntent_Deprecated.h>
#import <Intents/INSearchCallHistoryIntent_Deprecated.h>
#import <Intents/INStartAudioCallIntent_Deprecated.h>
#import <Intents/INSearchForMessagesIntent_Deprecated.h>
#import <Intents/INSendMessageIntent_Deprecated.h>
#import <Intents/INSetProfileInCarIntent_Deprecated.h>
