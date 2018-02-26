//
//  UICloudSharingController.h
//  UIKit
//
//  Copyright © 2016-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKitDefines.h>
#import <UIKit/UIViewController.h>
#import <UIKit/UIActivityItemProvider.h>

NS_ASSUME_NONNULL_BEGIN

@class UICloudSharingController, CKShare, CKContainer;

typedef NS_OPTIONS(NSUInteger, UICloudSharingPermissionOptions) {
    UICloudSharingPermissionStandard = 0, // Allow the user to configure the share with the standard set of options

    UICloudSharingPermissionAllowPublic = 1 << 0,    // The user is allowed to share publicly
    UICloudSharingPermissionAllowPrivate = 1 << 1,   // The user is allowed to share privately

    UICloudSharingPermissionAllowReadOnly = 1 << 2,  // The user is allowed to grant participants read-only permissions
    UICloudSharingPermissionAllowReadWrite = 1 << 3, // The user is allowed to grant participants read/write permissions
} NS_ENUM_AVAILABLE_IOS(10_0) __TVOS_PROHIBITED __WATCHOS_PROHIBITED;

__TVOS_PROHIBITED __WATCHOS_PROHIBITED
@protocol UICloudSharingControllerDelegate <NSObject>

- (void)cloudSharingController:(UICloudSharingController *)csc failedToSaveShareWithError:(NSError *)error;

// corresponds to CKShareTitleKey on the expected share
- (nullable NSString *)itemTitleForCloudSharingController:(UICloudSharingController *)csc;

@optional
// corresponds to CKShareThumbnailImageDataKey on the expected share
- (nullable NSData *)itemThumbnailDataForCloudSharingController:(UICloudSharingController *)csc;
// corresponds to CKShareTypeKey on the expected share
- (nullable NSString *)itemTypeForCloudSharingController:(UICloudSharingController *)csc;

- (void)cloudSharingControllerDidSaveShare:(UICloudSharingController *)csc;
- (void)cloudSharingControllerDidStopSharing:(UICloudSharingController *)csc;

@end

NS_CLASS_AVAILABLE_IOS(10_0) __TVOS_PROHIBITED __WATCHOS_PROHIBITED @interface UICloudSharingController : UIViewController

- (instancetype)initWithNibName:(nullable NSString *)nibNameOrNil bundle:(nullable NSBundle *)nibBundleOrNil NS_UNAVAILABLE;
- (nullable instancetype)initWithCoder:(NSCoder *)aDecoder NS_UNAVAILABLE;

/* Use this initializer when you want to share a set of CKRecords but haven't yet saved a CKShare.
 The preparation handler is called when it is time to save the share to the server.
 After ensuring the share and record have been saved to the server, invoke the preparationCompletionHandler
 with either the resulting CKShare, or an NSError if saving failed.
 */
- (instancetype)initWithPreparationHandler:(void (^)(UICloudSharingController *controller, void (^preparationCompletionHandler)(CKShare * _Nullable, CKContainer * _Nullable, NSError * _Nullable)))preparationHandler;

/* Use this initializer when you already have an active CKShare that was set up previously.
 */
- (instancetype)initWithShare:(CKShare *)share container:(CKContainer *)container;

@property (nonatomic, weak) id<UICloudSharingControllerDelegate> delegate;
@property (nonatomic, readonly, strong, nullable) CKShare *share;

/* Restrict the sharing invitation UI to specific types of share permissions. If set, only the specified combinations of permissions are selectable.
 */
@property (nonatomic) UICloudSharingPermissionOptions availablePermissions;

/* Returns an activity item source for use with UIActivityViewController.
 If the activity is selected, delegate methods will be called for the original instance of
 the sharing controller.
 */
- (id <UIActivityItemSource>)activityItemSource;

@end

NS_ASSUME_NONNULL_END
