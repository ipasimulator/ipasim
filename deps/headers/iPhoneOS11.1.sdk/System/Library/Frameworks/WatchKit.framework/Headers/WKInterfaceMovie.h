//
//  WKInterfaceMovie.h
//  WatchKit
//
//  Copyright (c) 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>
#import <WatchKit/WKInterfaceObject.h>
#import <WatchKit/WKInterfaceController.h>

@class WKImage;

NS_ASSUME_NONNULL_BEGIN

WK_AVAILABLE_WATCHOS_ONLY(2.0)
@interface WKInterfaceMovie : WKInterfaceObject

- (void)setMovieURL:(NSURL *)URL;
- (void)setVideoGravity:(WKVideoGravity)videoGravity;	// default is WKVideoGravityResizeAspect
- (void)setLoops:(BOOL)loops;

- (void)setPosterImage:(nullable WKImage *)posterImage;

@end

NS_ASSUME_NONNULL_END
