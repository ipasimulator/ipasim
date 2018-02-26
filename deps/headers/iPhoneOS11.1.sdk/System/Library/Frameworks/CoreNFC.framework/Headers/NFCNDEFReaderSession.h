//
//  NFCNDEFReaderSession.h
//  CoreNFC
//
//  Copyright © 2017 Apple. All rights reserved.
//

#ifndef NFCNDEFReaderSession_h
#define NFCNDEFReaderSession_h

#ifndef CoreNFC_H
#error Please import <CoreNFC/CoreNFC.h> from your source file
#endif

#import <Foundation/Foundation.h>

@class NFCReaderSession;
@class NFCNDEFReaderSession;

NS_ASSUME_NONNULL_BEGIN

/*!
 * @discussion Type Name Format value defined by NFC Data Exchange Format (NDEF) Technical Specification
 *             from NFC Forum.
 */
typedef NS_ENUM(uint8_t, NFCTypeNameFormat) {
    NFCTypeNameFormatEmpty             = 0x00,
    NFCTypeNameFormatNFCWellKnown      = 0x01,
    NFCTypeNameFormatMedia             = 0x02,
    NFCTypeNameFormatAbsoluteURI       = 0x03,
    NFCTypeNameFormatNFCExternal       = 0x04,
    NFCTypeNameFormatUnknown           = 0x05,
    NFCTypeNameFormatUnchanged         = 0x06
};

/*!
 * @class NFCNDEFPayload
 *
 * @discussion A NDEF message payload consists of Type Name Format, Type, Payload Identifier, and Payload data.
 */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, macos, tvos)
@interface NFCNDEFPayload : NSObject<NSSecureCoding>

@property (nonatomic, assign) NFCTypeNameFormat typeNameFormat;
@property (nonatomic, copy) NSData *type;
@property (nonatomic, copy) NSData *identifier;
@property (nonatomic, copy) NSData *payload;

- (instancetype)init NS_UNAVAILABLE;

@end

/*!
 * @class NFCNDEFMessage
 *
 * @discussion A NDEF message consists of payload records.
 */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, macos, tvos)
@interface NFCNDEFMessage : NSObject<NSSecureCoding>

@property (nonatomic, copy) NSArray<NFCNDEFPayload *>* records;

- (instancetype)init NS_UNAVAILABLE;

@end

/*!
 * @protocol NFCNDEFReaderSessionDelegate
 *
 * @discussion NDEF reader session callbacks.
 */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, macos, tvos)
@protocol NFCNDEFReaderSessionDelegate <NSObject>

@required

/*!
 * @method readerSession:didInvalidateWithError:
 *
 * @param session   The session object that is invalidated.
 * @param error     The error indicates the invalidation reason.
 *
 * @discussion      Gets called when a session becomes invalid.  At this point the client is expected to discard
 *                  the returned session object.
 */
- (void)readerSession:(NFCNDEFReaderSession *)session didInvalidateWithError:(NSError *)error;

/*!
 * @method readerSession:didDetectNDEFs:
 *
 * @param session   The session object used for tag detection.
 * @param messages  Array of @link NFCNDEFMessage @link/ objects. The order of the discovery on the tag is maintained.
 *
 * @discussion      Gets called when the reader detects NFC tag(s) with NDEF messages in the polling sequence.  Polling
 *                  is automatically restarted once the detected tag is removed from the reader's read range.
 */
- (void)readerSession:(NFCNDEFReaderSession *)session didDetectNDEFs:(NSArray<NFCNDEFMessage *> *)messages;

@end

#pragma mark - NDEF reader session

/*!
 * @class NFCNDEFReaderSession
 *
 * @discussion Reader session for processing NFC Data Exchange Format (NDEF) tags.  This session requires the "com.apple.developer.nfc.readersession.formats"
 *             entitlement in your process.  In addition your application's Info.plist must contain a non-empty usage description string.
 *
 * NOTE:
 * Only one NFCReaderSession can be active at any time in the system. Subsequent opened sessions will get queued up and processed by the system in FIFO order.
 */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, macos, tvos)
@interface NFCNDEFReaderSession : NFCReaderSession

/*!
 * @property readingAvailable
 *
 * @discussion YES if device supports NFC tag reading.
 */
@property (class, nonatomic, readonly) BOOL readingAvailable;

- (instancetype)init NS_UNAVAILABLE;

/*!
 * @method initWithDelegate:queue:
 *
 * @param delegate  The session will hold a weak ARC reference to this @link NFCNDEFReaderSessionDelegate @link/ object.
 * @param queue     A dispatch queue where NFCNDEFReaderSessionDelegate delegate callbacks will be dispatched to.  A <i>nil</i> value will
 *                  cause the creation of a serial dispatch queue internally for the session.  The session object will retain the provided dispatch queue.
 * @param invalidateAfterFirstRead  Session will automatically invalidate after the first NDEF tag is read successfully when this is set to YES, and -readerSession:didInvalidateWithError:
 *                                  will return NFCReaderSessionInvalidationErrorFirstNDEFTagRead in this case.
 *
 * @return          A new NFCNDEFReaderSession instance.
 *
 * @discussion      A NDEF reader session will automatically scan and detect NFC Forum tags that contain a valid NDEF message.  NFC Forum Tag type 1 to 5 that 
 *                  is NDEF formatted are supported.  A modal system UI will present once -beginSession is called to inform the start of the session; the UI sheet
 *                  is automatically dismissed when the session is invalidated either by the user or by calling -invalidateSession.  The alertMessage property shall be set
 *                  prior to -beginSession to display a message on the action sheet UI for the tag scanning operation.
 *
 *                  The reader session has the following properties:
 *                  + An opened session has a 60 seconds time limit restriction after -beginSession is called; -readerSession:didInvalidateWithError: will return
 *                  NFCReaderSessionInvalidationErrorSessionTimeout error when the time limit is reached.
 *                  + Only 1 active reader session is allowed in the system; -readerSession:didInvalidateWithError: will return NFCReaderSessionInvalidationErrorSystemIsBusy
 *                  when a new reader session is initiated by -beginSession when there is an active reader session.  
 *                  + -readerSession:didInvalidateWithError: will return NFCReaderSessionInvalidationErrorUserCanceled when user clicks on the done button on the UI.
 *                  + -readerSession:didInvalidateWithError: will return NFCReaderSessionInvalidationErrorSessionTerminatedUnexpectedly when the client application enters
 *                  the background state.
 *                  + -readerSession:didInvalidateWithError: will return NFCReaderErrorUnsupportedFeature when 1) reader mode feature is not available on the hardware,
 *                  2) client application does not have the required entitlement.
 */
- (instancetype)initWithDelegate:(id<NFCNDEFReaderSessionDelegate>)delegate queue:(nullable dispatch_queue_t)queue invalidateAfterFirstRead:(BOOL)invalidateAfterFirstRead NS_DESIGNATED_INITIALIZER;

NS_ASSUME_NONNULL_END

@end

#endif
