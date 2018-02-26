//
//  MPMoviePlayerController_iAdPreroll.h
//  iAd
//
//  Copyright 2012 Apple, Inc. All rights reserved.
//

#import <TargetConditionals.h>

#if TARGET_OS_IOS && TARGET_OS_EMBEDDED
#import <MediaPlayer/MediaPlayer.h>

NS_ASSUME_NONNULL_BEGIN

/*!
 * @category MPMoviePlayerController (iAdPreroll)
 *
 * @dependency MediaPlayer.framework
 * 
 * @discussion
 * Adds optional pre-roll advertising support to MPMoviePlayerController.
 */
@interface MPMoviePlayerController (iAdPreroll)

/*!
 * @method +preparePrerollAds
 *
 * @discussion
 * Inform iAd that the application intends to use MPMoviePlayerController's
 * -playPrerollAdWithCompletionHandler: API. Ad metadata will be fetched eagerly,
 * increasing the likelihood of an ad being available when first requested.
 */
+ (void)preparePrerollAds NS_AVAILABLE_IOS(7_0);

/*!
 * @method -playPrerollAdWithCompletionHandler:
 *
 * @discussion
 * Request playback of a pre-roll video iAd.
 *
 * When the completion handler is called, the MPMoviePlayerController's -play
 * API can be called if a contentURL or asset is configured, or the controller's
 * view can be dismissed.
 *
 * The completion handler's error argument will be non-nil if the pre-roll ad
 * could not be played. Errors can occur for a number of reasons, such as lack
 * of ad inventory, exceeding the maximum pre-roll ad playback frequency, iAd
 * account configuration issues, and media playback issues. See ADError for an
 * exhaustive list of possible errors.
 *
 * Passing nil as the completion handler is an error and will throw an exception.
 *
 * NOTE: The MPMoviePlayerController must not be playing (or configured to
 * autoplay) when -playPrerollAdWithCompletionHandler: is called. If the
 * MPMoviePlayerController starts regular playback during pre-roll playback, the
 * ad will be skipped immediately.
 */
- (void)playPrerollAdWithCompletionHandler:(void (^)(NSError * _Nullable error))completionHandler NS_AVAILABLE_IOS(7_0);

/*!
 * @method -cancelPreroll
 *
 * @discussion
 * Cancel pre-roll video ad playback.
 */
- (void)cancelPreroll NS_AVAILABLE_IOS(8_0);

@end

NS_ASSUME_NONNULL_END

#endif

