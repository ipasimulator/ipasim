//
//  WKInterfaceInlineMovie.h
//  WatchKit
//
//  Copyright © 2016 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>
#import <WatchKit/WKInterfaceObject.h>

@class WKImage;

NS_ASSUME_NONNULL_BEGIN

WK_AVAILABLE_WATCHOS_ONLY(3.0)

@interface WKInterfaceInlineMovie : WKInterfaceObject

- (void)setMovieURL:(NSURL *)URL;
- (void)setVideoGravity:(WKVideoGravity)videoGravity;	// default is WKVideoGravityResizeAspect
- (void)setLoops:(BOOL)loops;                           // default is NO
- (void)setAutoplays:(BOOL)autoplays;                   // default is YES

- (void)setPosterImage:(nullable WKImage *)posterImage;

- (void)play;
- (void)playFromBeginning;
- (void)pause;

@end

NS_ASSUME_NONNULL_END
