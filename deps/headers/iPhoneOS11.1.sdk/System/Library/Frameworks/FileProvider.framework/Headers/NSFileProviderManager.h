//
//  NSFileProviderManager.h
//  FileProvider
//
//  Copyright (c) 2016-2017 Apple Inc. All rights reserved.
//

#import <FileProvider/NSFileProviderDefines.h>
#import <FileProvider/NSFileProviderItem.h>

NS_ASSUME_NONNULL_BEGIN

@class NSURLSessionTask;
@class NSFileProviderDomain;

API_AVAILABLE(ios(11.0)) API_UNAVAILABLE(macos, watchos, tvos)
@interface NSFileProviderManager : NSObject

- (instancetype)init NS_UNAVAILABLE;

/**
 Call this method either in the app or in the extension.

 The file provider manager is the objects that lets you communicate with the file
 provider framework, when you have background activity (e.g when you receive a
 push or when an NSURLSessionTask starts or completes.)  The file provider
 framework will invoke your file provider extension in response to those calls if appropriate.
 */
@property (class, readonly, strong) NSFileProviderManager *defaultManager;

/**
 Call this method either in the app or in the extension to trigger an enumeration,
 typically in response to a push.

 Set the containerItemIdentifier to the identifier of the enumerated container that
 was specified in
 -[NSFileProviderExtension enumeratorForContainerItemIdentifier:error:]

 This will trigger another call to
 -[NSFileProviderEnumerator enumerateChangesForObserver:fromSyncAnchor:]

 and the UI will be refreshed, giving the user live updates on the presented
 enumeration.

 If you have a change in the working set, call this method with
 containerItemIdentifier set to NSFileProviderWorkingSetContainerItemIdentifier,
 even if there is no live enumeration for this item.  The working set is cached
 on the device and it's important to keep the cache in sync.

 In addition to using this method, your application/extension can register for pushes
 using the PKPushTypeFileProvider push type. Pushes of the form
 {
     container-identifier = "<identifier>"
 }
 with a topic of "<your application identifier>.pushkit.fileprovider" will be
 translated into a call to signalEnumeratorForContainerItemIdentifier:completionHandler:.
 */
- (void)signalEnumeratorForContainerItemIdentifier:(NSFileProviderItemIdentifier)containerItemIdentifier completionHandler:(void (^)(NSError * __nullable error))completion NS_SWIFT_NAME(signalEnumerator(for:completionHandler:));

/**
 Registers the given NSURLSessionTask to be responsible for the specified item.
 A given item can only have one task registered at a time. The task must be suspended
 at the time of calling.
 The task's progress is displayed on the item when the task is executed.
 */
- (void)registerURLSessionTask:(NSURLSessionTask *)task forItemWithIdentifier:(NSFileProviderItemIdentifier)identifier completionHandler:(void (^)(NSError * __nullable error))completion;

/**
 The purpose identifier of your file provider extension. A coordination using a
 file coordinator with this purpose identifier set will not trigger your file
 provider extension. You can use this to e.g. perform speculative work on behalf
 of the file provider from the main app.
 */
@property(nonatomic, readonly) NSString *providerIdentifier;

/**
 The root URL for provided documents. This URL is derived by consulting the
 NSExtensionFileProviderDocumentGroup property on your extension. The document
 storage URL is the folder "File Provider Storage" in the corresponding
 container.
 */
@property(nonatomic, readonly) NSURL *documentStorageURL;

/**
 Writes out a placeholder at the specified URL. The placeholder is used in place
 of the actual file for operations that do not require the file's actual data to
 be on disk:
 - if attributes are requested by an application via the
 getPromisedItemResourceValue: method on NSURL
 - or via a coordination with the
 NSFileCoordinatorReadingImmediatelyAvailableMetadataOnly flag set
 - to verify whether an application has access to a file

 Your extension should provide placeholders by implementing the
 providePlaceholderAtURL: method, but your application may choose to proactively
 write out placeholders to facilitate access to files. This is especially useful
 if your application wants to actively hand out a file URL, e.g. using
 UIActivityViewController, in which case it should ensure that either the file
 or a placeholder is present on disk first.

 The path of the placeholder is fixed and must be determined in advance by
 calling the placeholderURLForURL: method.
 */
+ (BOOL)writePlaceholderAtURL:(NSURL *)placeholderURL
                 withMetadata:(NSFileProviderItem)metadata
                        error:(NSError **)error;

/**
 Returns the designated placeholder URL for a given file URL. Used in
 conjunction with writePlaceholderAtURL.
 */
+ (NSURL *)placeholderURLForURL:(NSURL *)url;

/**
 Register a domain in which items can be stored.
 */
+ (void)addDomain:(NSFileProviderDomain *)domain completionHandler:(void(^)(NSError *_Nullable))completionHandler;

/**
 Remove a domain.
 */
+ (void)removeDomain:(NSFileProviderDomain *)domain completionHandler:(void(^)(NSError *_Nullable))completionHandler;

/**
 Get all registered domains.
 */
+ (void)getDomainsWithCompletionHandler:(void (^)(NSArray<NSFileProviderDomain *> *domains, NSError * _Nullable error))completionHandler;

/**
 Remove all registered domains.
 */
+ (void)removeAllDomainsWithCompletionHandler:(void(^)(NSError *_Nullable))completionHandler;

+ (nullable instancetype)managerForDomain:(NSFileProviderDomain *)domain;

@end

NS_ASSUME_NONNULL_END
