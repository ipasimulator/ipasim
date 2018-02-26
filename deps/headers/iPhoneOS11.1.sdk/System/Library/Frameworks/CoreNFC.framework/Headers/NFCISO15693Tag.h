//
//  NFCISO15693Tag.h
//  CoreNFC
//
//  Copyright © 2017 Apple. All rights reserved.
//

#ifndef NFCISO15693Tag_h
#define NFCISO15693Tag_h

#ifndef CoreNFC_H
#error Please import <CoreNFC/CoreNFC.h> from your source file
#endif


#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class NFCTagCommandConfiguration;
@protocol NFCTag;

/*!
 * @class       NFCISO15693CustomCommandConfiguration
 *
 * @discussion  Configuration options for the Manufacturer Custom command.
 */

API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, macos, tvos)
@interface NFCISO15693CustomCommandConfiguration : NFCTagCommandConfiguration

/*!
 * @discussion  Manufacturer code. Valid range is 0x00 to 0xFF.
 */
@property (nonatomic, assign) NSUInteger manufacturerCode;

/*!
 * @discussion  Manufacturer Custom Command Index.  Valid range is 0xA0 to 0xDF.
 */
@property (nonatomic, assign) NSUInteger customCommandCode;

/*!
 * @discussion  Custom request data.
 */
@property (nonatomic, copy) NSData * requestParameters;

/*!
 * @method initWithManufacturerCode:customCommandCode:requestParameters:
 *
 * @param manufacturerCode      8 bits manufacturer code.
 * @param customCommandCode     8 bits custom command code.  Valid range is 0xA0 to 0xDF.
 * @param requestParameters     Optional custom request parameters.
 *
 * @discussion  Initialize with default zero maximum retry and zero retry interval.
 */
- (instancetype)initWithManufacturerCode:(NSUInteger)manufacturerCode
                       customCommandCode:(NSUInteger)customCommandCode
                       requestParameters:(nullable NSData*)requestParameters;

/*!
 * @method initWithManufacturerCode:customCommandCode:requestParameters:maximumRetries:retryInterval:
 *
 * @param manufacturerCode      8 bits manufacturer code.
 * @param customCommandCode     8 bits custom command code.  Valid range is 0xA0 to 0xDF.
 * @param requestParameters     Optional custom request parameters.
 * @param maximumRetries        Maximum number of retry attempt when tag response is not recevied.
 * @param retryInterval         Time interval wait between each retry attempt.
 */
- (instancetype)initWithManufacturerCode:(NSUInteger)manufacturerCode
                       customCommandCode:(NSUInteger)customCommandCode
                       requestParameters:(nullable NSData*)requestParameters
                          maximumRetries:(NSUInteger)maximumRetries
                           retryInterval:(NSTimeInterval)retryInterval;
@end

/*!
 * @class       NFCISO15693ReadMultipleBlocksConfiguration
 *
 * @discussion  Configuration options for the Read Multiple Blocks command.
 */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, macos, tvos)
@interface NFCISO15693ReadMultipleBlocksConfiguration : NFCTagCommandConfiguration

/*!
 * @discussion  Range to read in blocks.  Valid start index range is 0x00 to 0xFF.  Length shall not be 0.
 */
@property (nonatomic, assign) NSRange range;

/*!
 * @discussion  Number of blocks to read per Read Multiple Blocks command. This may be limited by the tag hardware.
 */
@property (nonatomic, assign) NSUInteger chunkSize;

/*!
 * @discussion  Initialize with default zero maximum retry and zero retry interval.
 */
- (instancetype)initWithRange:(NSRange)range
                    chunkSize:(NSUInteger)chunkSize;
/*!
 * @method initWithRange:chunkSize:maximumRetries:retryInterval:
 *
 * @param range             Read range specify by the starting block index and the total number of blocks.
 * @param chunkSize         Specify number of blocks parameter for the Read multiple blocks command.
 * @param maximumRetries    Maximum number of retry attempt when tag response is not recevied.
 * @param retryInterval     Time interval wait between each retry attempt.
 */
- (instancetype)initWithRange:(NSRange)range
                    chunkSize:(NSUInteger)chunkSize
               maximumRetries:(NSUInteger)maximumRetries
                retryInterval:(NSTimeInterval)retryInterval;

@end

/*!
 * @protocol NFCISO15693Tag
 *
 * @discussion  A @link NFCISO15693ReaderSession @link/ reader session returns an instance conforming to this protocol
 *              when a tag is detected.  Unless it is specified all block completion handlers are dispatched on the
 *              [NFCISO15693ReaderSession sessionQueue] session work queue that is associated with the tag.
 *              This tag class requires the "com.apple.developer.nfc.readersession.iso15693.tag-identifiers" entitlement in your process.
 */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, macos, tvos)
@protocol NFCISO15693Tag <NFCTag>

@required

/*!
 * @discussion The 64 bit hardware UID of the tag. Data is in Big Endian byte order.
 */
@property (nonatomic, readonly, copy) NSData * identifier;

/*!
 * @discussion  The IC manufacturer code (bits 56 – 49) in UID according to ISO/IEC 7816-6:2004.
 */
@property (nonatomic, readonly) NSUInteger icManufacturerCode;

/*!
 * @discussion  The IC serial number (bits 48 – 1) in UID assigned by the manufacturer.  Data is in Big Endian byte order.
 */
@property (nonatomic, readonly, copy) NSData * icSerialNumber;

/*!
 * @method sendCustomCommandWithConfiguration:completionHandler:
 *
 * @param commandConfiguration  Configuration for the Manufacturer Custom Command.
 * @param completionHandler     Completion handler called when the operation is completed.  error is nil if operation succeeds.
 *                              A @link NFCISO15693TagResponseErrorDomain @link/ error is returned when the tag responded to the command
 *                              with an error, and the error code value is defined in ISO15693-3 specification.
 *
 * @discussion Send a manufacturer dependent custom command using command code range from 0xA0 to 0xDF.  Refer to ISO15693-3
 *             specification for details.
 */
- (void)sendCustomCommandWithConfiguration:(NFCISO15693CustomCommandConfiguration *)commandConfiguration
                          completionHandler:(void(^)(NSData * customResponseParameters, NSError * _Nullable error))completionHandler;

/*!
 * @method readMultipleBlocksWithConfiguration:completionHandler:
 *
 * @param readConfiguration Configuration For the Read Multiple Blocks command.
 * @param completionHandler Completion handler called when the operation is completed.  error is nil if operation succeeds.
 *                          A @link NFCISO15693TagResponseErrorDomain @link/ error is returned when the tag responded to the command
 *                          with an error, and the error code value is defined in ISO15693-3 specification. Successfully read data blocks
 *                          will be return from NSData object.  All blocks are concatenated into the NSData object.
 *
 * @discussion  Performs read operation using Read Multiple Blocks command (0x23 command code) as defined in IOS15693-3 specification.
 *              Multiple Read Multiple Blocks commands will be sent if necessary to complete the operation.
 */
- (void)readMultipleBlocksWithConfiguration:(NFCISO15693ReadMultipleBlocksConfiguration *)readConfiguration
                           completionHandler:(void(^)(NSData * data, NSError * _Nullable error))completionHandler;

@end

NS_ASSUME_NONNULL_END

#endif /* NFCISO15693Tag_h */
