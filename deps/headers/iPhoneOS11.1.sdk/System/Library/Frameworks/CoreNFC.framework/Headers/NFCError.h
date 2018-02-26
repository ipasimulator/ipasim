//
//  NFCError.h
//  CoreNFC
//
//  Copyright © 2017 Apple. All rights reserved.
//

#ifndef NFCError_h
#define NFCError_h

#ifndef CoreNFC_H
#error Please import <CoreNFC/CoreNFC.h> from your source file
#endif

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, macos, tvos)
extern NSString * const NFCErrorDomain;

/*!
 * @enum NFCReaderError
 *
 * @discussion Possible errors returned by CoreNFC framework reader session.
 */
typedef NS_ERROR_ENUM(NFCErrorDomain, NFCReaderError) {
    NFCReaderErrorUnsupportedFeature = 1,
    NFCReaderErrorSecurityViolation,

    NFCReaderTransceiveErrorTagConnectionLost = 100,
    NFCReaderTransceiveErrorRetryExceeded,
    NFCReaderTransceiveErrorTagResponseError,

    NFCReaderSessionInvalidationErrorUserCanceled = 200,
    NFCReaderSessionInvalidationErrorSessionTimeout,
    NFCReaderSessionInvalidationErrorSessionTerminatedUnexpectedly,
    NFCReaderSessionInvalidationErrorSystemIsBusy,
    NFCReaderSessionInvalidationErrorFirstNDEFTagRead,

    NFCTagCommandConfigurationErrorInvalidParameters = 300,
};

#pragma mark - ISO15693 specific command response error code

/*!
 *  Key in NSError userInfo dictionary.  The corresponding value is the NSUInteger error code from tag's response.
 *  Refer to ISO15693 specification for the error code values.
 */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, macos, tvos)
extern NSString * const NFCISO15693TagResponseErrorKey;


NS_ASSUME_NONNULL_END

#endif /* CNFCError_h */
