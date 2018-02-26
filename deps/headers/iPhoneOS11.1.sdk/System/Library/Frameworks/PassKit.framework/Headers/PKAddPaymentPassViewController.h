//
//  PKAddPaymentPassViewController.h
//  PassKit
//
//  Copyright © 2015 Apple, Inc. All rights reserved.
//

#if TARGET_OS_IPHONE

#import <UIKit/UIKit.h>
#import <PassKit/PKConstants.h>
NS_ASSUME_NONNULL_BEGIN

@class PKAddPaymentPassViewController, PKPaymentPass, PKLabeledValue;

typedef NS_ENUM(NSInteger, PKAddPaymentPassError) {
    PKAddPaymentPassErrorUnsupported,
    PKAddPaymentPassErrorUserCancelled,
    PKAddPaymentPassErrorSystemCancelled
} API_AVAILABLE(ios(9.0));

API_AVAILABLE(ios(9.0))
@interface PKAddPaymentPassRequestConfiguration : NSObject

/* Schemes defined in PKConstants.h.
 * Supported Schemes:
 *  PKEncryptionSchemeECC_V2:
 *      ephemeralPublicKey
 *  PKEncryptionSchemeRSA_V2:
 *      wrappedKey
 */
- (nullable instancetype)initWithEncryptionScheme:(PKEncryptionScheme)encryptionScheme NS_DESIGNATED_INITIALIZER;

@property (nonatomic, copy, readonly) PKEncryptionScheme encryptionScheme;

/* Display Properties:
 *  At least one of cardholder name or primary account suffix must be supplied.
 */
@property (nonatomic, copy, nullable) NSString *cardholderName;
@property (nonatomic, copy, nullable) NSString *primaryAccountSuffix;

@property (nonatomic, copy) NSArray<PKLabeledValue *> *cardDetails API_AVAILABLE(ios(10.1));

@property (nonatomic, copy, nullable) NSString *localizedDescription;

/* Pass Library Filters:
 *  If the filtered set is empty, then all filter will be ignored.
 */
@property (nonatomic, copy, nullable) NSString *primaryAccountIdentifier;

/* Filters introduction page to a specific network - does not function as a restriction.
 */
@property (nonatomic, copy, nullable) PKPaymentNetwork paymentNetwork;

@property (nonatomic, assign) BOOL requiresFelicaSecureElement API_AVAILABLE(ios(10.1));

@end

NS_CLASS_AVAILABLE_IOS(9_0) @interface PKAddPaymentPassRequest : NSObject

- (instancetype)init NS_DESIGNATED_INITIALIZER;

@property (nonatomic, copy, nullable) NSData *encryptedPassData;
@property (nonatomic, copy, nullable) NSData *activationData;

/* Scheme dependent properties:
 */
@property (nonatomic, copy, nullable) NSData *ephemeralPublicKey;
@property (nonatomic, copy, nullable) NSData *wrappedKey;

@end

@protocol PKAddPaymentPassViewControllerDelegate<NSObject>

/* Certificates is an array of NSData, each a DER encoded X.509 certificate, with the leaf first and root last.
 * The continuation handler must be called within 20 seconds or an error will be displayed. 
 * Subsequent to timeout, the continuation handler is invalid and invocations will be ignored.
 */
- (void)addPaymentPassViewController:(PKAddPaymentPassViewController *)controller
 generateRequestWithCertificateChain:(NSArray<NSData *> *)certificates
                               nonce:(NSData *)nonce
                      nonceSignature:(NSData *)nonceSignature
                   completionHandler:(void(^)(PKAddPaymentPassRequest *request))handler;

/* Error parameter will use codes from the PKAddPaymentPassError enumeration, using the PKPassKitErrorDomain domain.
 */
- (void)addPaymentPassViewController:(PKAddPaymentPassViewController *)controller didFinishAddingPaymentPass:(nullable PKPaymentPass *)pass error:(nullable NSError *)error;

@end

API_AVAILABLE(ios(9.0))
@interface PKAddPaymentPassViewController : UIViewController

+ (BOOL)canAddPaymentPass;

/* This controller should be presented with -[UIViewController presentViewController:animated:completion:].
 */
- (nullable instancetype)initWithRequestConfiguration:(PKAddPaymentPassRequestConfiguration *)configuration
                                             delegate:(nullable id<PKAddPaymentPassViewControllerDelegate>)delegate NS_DESIGNATED_INITIALIZER;

@property (nonatomic, weak, nullable) id<PKAddPaymentPassViewControllerDelegate> delegate;

@end

NS_ASSUME_NONNULL_END

#endif
