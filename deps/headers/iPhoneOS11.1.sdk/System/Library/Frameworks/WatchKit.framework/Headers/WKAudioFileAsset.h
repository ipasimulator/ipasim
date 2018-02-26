//
//  WKAudioFileAsset.h
//  WatchKit
//
//  Copyright (c) 2015 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <WatchKit/WKDefines.h>

/*!
 @class		WKAudioFileAsset
 
 @abstract
 WatchKit corollary to AVFoundation AVAsset abstract class
 
 @discussion
 This class provides the functionality of AVAsset for Watch OS apps. Only file-based assets are allowed.
*/

NS_ASSUME_NONNULL_BEGIN

WK_AVAILABLE_WATCHOS_ONLY(2.0)
@interface WKAudioFileAsset : NSObject

- (instancetype)init NS_UNAVAILABLE;

/*!
 @method		assetWithURL:
 @abstract		Returns an instance of WKAudioFileAsset for inspection of a media resource.
 @param		URL
 An instance of NSURL that references a file-based media resource.
 @result		An instance of WKAudioFileAsset.
 @discussion	Returns a newly allocated instance of a subclass of WKAudioFileAsset initialized with the specified URL.
                Title, ablumTitle, and artist properties are initialized to the values found in the common metadata of the media resource
 */
+ (instancetype)assetWithURL:(NSURL *)URL;

/*!
 @method		assetWithURL:title:albumTitle:artist:
 @abstract		Returns an instance of WKAudioFileAsset for inspection of a media resource.
 @param		URL
 An instance of NSURL that references a file-based media resource.
 @param		title
 Title string to use for the Now Playing controls. If nil, value in common metadata of the media resource will be used. If no value is found in common metadata, the file name will be used.
 @param		albumTitle
 Album Title string to use for the Now Playing controls. If nil, value in common metadata of the media resource will be used.
 @param		artist
 Artist string to use for the Now Playing controls. If nil, value in common metadata of the media resource will be used.
 @result		An instance of WKAudioFileAsset.
 @discussion	Returns a newly allocated instance of a subclass of WKAudioFileAsset initialized with the specified URL.
 */
+ (instancetype)assetWithURL:(NSURL *)URL title:(nullable NSString *)title albumTitle:(nullable NSString *)albumTitle artist:(nullable NSString *)artist;

@property (nonatomic, readonly) NSURL *URL;
@property (nonatomic, readonly) NSTimeInterval duration;
@property (nonatomic, readonly, nullable) NSString *title;
@property (nonatomic, readonly, nullable) NSString *albumTitle;
@property (nonatomic, readonly, nullable) NSString *artist;
@end

NS_ASSUME_NONNULL_END
