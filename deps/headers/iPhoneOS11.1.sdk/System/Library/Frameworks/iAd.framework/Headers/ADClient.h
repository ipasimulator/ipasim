//
//  ADClient.h
//  iAd
//
//  Copyright 2013 Apple, Inc. All rights reserved.
//
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

NS_CLASS_AVAILABLE_IOS(7_1) @interface ADClient : NSObject

/*!
 * @method sharedClient
 *
 * @return
 * The shared singleton instance of ADClient.
 *
 * @discussion
 * ADClient is a singleton object.
 */
+ (ADClient *)sharedClient NS_AVAILABLE_IOS(7_1);

/*!
 * @const ADClientErrorDomain
 *
 * @discussion
 * Error domain for NSErrors passed to the completionHandler as a 
 * result of calling:
 *
 *   • -[[ADClient SharedClient] requestAttributionDetailsWithBlock]
 *
 */
extern NSString * const ADClientErrorDomain;

/*!
 * @enum ADClientError
 *
 * @const ADClientErrorUnknown
 * General errors that aren't covered by one of the more specific error reasons.
 * This is generally related to connectivity issues.
 *
 * @const ADClientErrorLimitAdTracking
 * The device has Limit Ad Tracking enabled. It will not be possible to recieve
 * attribution details for app purchases made on this device.
 *
 * @discussion
 * Error codes for NSErrors passed to the completionHandler block
 * when calling the requestAttributionDetailsWithBlock method.
 */
typedef NS_ENUM(NSInteger, ADClientError) {
    ADClientErrorUnknown = 0,
    ADClientErrorLimitAdTracking = 1,
};

/*!
 * @method determineAppInstallationAttributionWithCompletionHandler:
 *
 * @param completionHandler
 * A block accepting one BOOL argument that will be called when app installation
 * attribution status has been determined. If this installation of the app is
 * attributed to an iAd impression, the completion handler will be called with
 * YES. Otherwise, or if the user has enabled Limit Ad Tracking, the completion
 * handler will be called with NO.
 *
 * The handler will be called on an arbitrary queue.
 *
 * @discussion
 * Provides a way for an app to determine if it was installed by the user in
 * response to seeing an iAd for the app.
 */
- (void)determineAppInstallationAttributionWithCompletionHandler:(void (^)(BOOL appInstallationWasAttributedToiAd))completionHandler NS_DEPRECATED_IOS(7_1, 9_0, "Use requestAttributionDetailsWithBlock instead.");

/*!
 * @method lookupAdConversionDetails:
 *
 * @param completionHandler
 * A block which will be called with the app purchase date and the date at which
 * the user saw an iAd for the app. If no conversion has been tracked, or if
 * Limit Ad Tracking is enabled on the device, both dates will be nil.
 *
 * The handler will be called on an arbitrary queue.
 *
 * @discussion
 * Provides a way for an app to determine when an iAd was shown to the user
 * which resulted in the user's purchase of the app.
 */
- (void)lookupAdConversionDetails:(void (^)(NSDate *appPurchaseDate, NSDate * _Nullable iAdImpressionDate))completionHandler NS_DEPRECATED_IOS(8_0, 9_0, "Use requestAttributionDetailsWithBlock instead.");

/*!
 * @method requestAttributionDetailsWithBlock:
 *
 * @param completionHandler
 * A block which will be called with details related to the attribution status of the app.
 * The attributionDetails dictionary will contain purchase and impression dates
 * as well as other specific campaign related information provided by iAd. If the attributionDetails
 * dictionary is nil, an NSError is passed with an ADClientError enum.
 *
 * The handler will be called on an arbitrary queue.
 *
 * @discussion
 * Provides a way for an app to determine when an iAd was shown to the user
 * which resulted in the user's purchase of the app.
 */
- (void)requestAttributionDetailsWithBlock:(void (^)(NSDictionary<NSString *, NSObject *> * _Nullable attributionDetails, NSError * _Nullable error))completionHandler NS_AVAILABLE_IOS(9_0);

/*!
 * @method addClientToSegments:replaceExisting:
 *
 * @param segmentIdentifiers
 * Array of NSString objects identifying which segments to add the client to.
 * May be nil.
 *
 * @param replaceExisting
 * If YES, the client will be removed from all existing segments prior to
 * being added to the specified segments.
 *
 * @discussion
 * Enables apps to add users to custom segments owned and defined by the calling
 * application.  If Limit Ad Tracking is enabled on the device, this method will
 * have no effect.
 */
- (void)addClientToSegments:(NSArray<NSString *> *)segmentIdentifiers replaceExisting:(BOOL)replaceExisting NS_AVAILABLE_IOS(8_0);

@end

NS_ASSUME_NONNULL_END

