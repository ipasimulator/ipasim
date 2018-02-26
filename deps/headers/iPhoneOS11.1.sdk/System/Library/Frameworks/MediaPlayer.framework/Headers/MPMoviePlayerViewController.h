//
//  MPMoviePlayerViewController.h
//  MediaPlayer
//
//  Copyright 2009-2015 Apple, Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <MediaPlayer/MediaPlayerDefines.h>
#import <UIKit/UIViewController.h>

@class MPMoviePlayerController;

MP_DEPRECATED("Use AVPlayerViewController in AVKit.", ios(3.2, 9.0))
MP_PROHIBITED(tvos)
@interface MPMoviePlayerViewController : UIViewController

- (instancetype)initWithContentURL:(NSURL *)contentURL NS_DESIGNATED_INITIALIZER;

@property (nonatomic, readonly) MPMoviePlayerController *moviePlayer;

@end

// -----------------------------------------------------------------------------
// UIViewController Additions
// Additions to present a fullscreen movie player as a modal view controller using the standard movie player transition.

@interface UIViewController (MPMoviePlayerViewController)

- (void)presentMoviePlayerViewControllerAnimated:(MPMoviePlayerViewController *)moviePlayerViewController MP_DEPRECATED("Use AVPlayerViewController in AVKit.", ios(3.2, 9.0)) MP_PROHIBITED(tvos);
- (void)dismissMoviePlayerViewControllerAnimated MP_DEPRECATED("Use AVPlayerViewController in AVKit.", ios(3.2, 9.0)) MP_PROHIBITED(tvos);

@end
