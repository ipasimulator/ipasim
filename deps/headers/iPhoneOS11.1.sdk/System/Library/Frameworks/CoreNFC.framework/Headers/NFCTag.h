//
//  NFCTag.h
//  CoreNFC
//
//  Copyright © 2017 Apple. All rights reserved.
//

#ifndef NFCTag_h
#define NFCTag_h

#ifndef CoreNFC_H
#error Please import <CoreNFC/CoreNFC.h> from your source file
#endif

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/*!
 * @enum NFCTagType
 *
 * @constant NFCTagTypeISO15693    ISO15693 tag.
 */
typedef NS_ENUM(NSUInteger, NFCTagType) {
    NFCTagTypeISO15693 = 1,
};

@protocol NFCReaderSession;

/*!
 * @protocol NFCTag
 *
 * @discussion A NFC / RFID tag object conforms to this protocol.  The NFCReaderSession returns an instance of this type when a tag is detected.
 */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, macos, tvos)
@protocol NFCTag <NSObject, NSSecureCoding, NSCopying>

@required

/*!
 * @property type
 * 
 * @discussion See @link CNFCTagType @link/
 */
@property (nonatomic, readonly, assign) NFCTagType type;

/*!
 * @property    session
 *
 * @discussion  Session that provides this tag.
 */
@property (nonatomic, weak, readonly) id<NFCReaderSession> session;

/*!
 * @property available:
 *
 * @return      <i>YES</i> if tag is available in the current reader session.  A tag remove from the RF field will become
 *              unavailable.
 *
 * @discussion  Check whether a detected tag is available.
 */
@property (nonatomic, getter=isAvailable, readonly) BOOL available;

@end

#pragma mark - Tag command configuration

/*!
 * @interface   NFCTagCommandConfiguration
 *
 * @discussion  Define configuration parameters for tag commands.
 */
API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(watchos, macos, tvos)
@interface NFCTagCommandConfiguration : NSObject<NSCopying>

/*!
 * @discussion  Maximum number of retries.  Valid value is 0 to 256.  Default is 0.
 */
@property (nonatomic, assign) NSUInteger maximumRetries;

/*!
 * @discussion  Delay in seconds before retry occurs.  Default is 0.
 */
@property (nonatomic, assign) NSTimeInterval retryInterval;

@end

NS_ASSUME_NONNULL_END

#endif /* NFCTag_h */
