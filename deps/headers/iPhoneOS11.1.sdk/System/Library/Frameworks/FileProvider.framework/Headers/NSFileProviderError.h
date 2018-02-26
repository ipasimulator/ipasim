//
//  NSFileProviderError.h
//  FileProvider
//
//  Copyright (c) 2014-2017 Apple Inc. All rights reserved.
//

#import <FileProvider/NSFileProviderDefines.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const NSFileProviderErrorDomain API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos);

FOUNDATION_EXPORT NSString * const NSFileProviderErrorCollidingItemKey API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos);
FOUNDATION_EXPORT NSString * const NSFileProviderErrorNonExistentItemIdentifierKey API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos);

typedef NS_ERROR_ENUM(NSFileProviderErrorDomain, NSFileProviderErrorCode) {
    NSFileProviderErrorNotAuthenticated  = -1000, /**< The user credentials cannot be verified */
    NSFileProviderErrorFilenameCollision = -1001, /**< An item already exists with the same parentItemIdentifier and filename (or with a filename differing only in case.)
                                                       Please use -[NSError (NSFileProviderError) fileProviderErrorForCollisionWithItem:] to build an error with this code. */
    NSFileProviderErrorSyncAnchorExpired = -1002, /**< The value of the sync anchor is too old, and the system must re-sync from scratch */
    NSFileProviderErrorPageExpired        = NSFileProviderErrorSyncAnchorExpired, /**< The value of the page token is too old, and the system must re-sync from scratch */
    NSFileProviderErrorInsufficientQuota = -1003, /**< The item has not been uploaded because it would push the account over quota */
    NSFileProviderErrorServerUnreachable = -1004, /**< Connecting to the servers failed */
    NSFileProviderErrorNoSuchItem        = -1005  /**< The requested item doesn't exist
                                                       Please use -[NSError (NSFileProviderError) fileProviderErrorForNonExistentItemWithIdentifier:] to build an error with this code. */
} API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos);

@interface NSError (NSFileProviderError)
+ (instancetype)fileProviderErrorForCollisionWithItem:(NSFileProviderItem)existingItem API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos);
+ (instancetype)fileProviderErrorForNonExistentItemWithIdentifier:(NSFileProviderItemIdentifier)itemIdentifier API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos);
@end

NS_ASSUME_NONNULL_END
