//
//  NKNSURLConnectionAdditions.h
//  NewsstandKit
//
//  Copyright 2011 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@class NKAssetDownload;


/*!
 @category   NKAssetDownloadAdditions(NSURLConnection)
 @abstract   NKAssetDownload extensions to NSURLConnection.
 @discussion This category provides a convenient way to look up an
 NKAssetDownload that is related to a NSURLConnection.
 */
@interface NSURLConnection (NKAssetDownloadAdditions)

/*!
 @property   newsstandAssetDownload
 @abstract   A pointer to the asset download that this connection is associated with.
 */
@property (readonly, weak, nullable) NKAssetDownload *newsstandAssetDownload NS_AVAILABLE_IOS(5_0);

@end
