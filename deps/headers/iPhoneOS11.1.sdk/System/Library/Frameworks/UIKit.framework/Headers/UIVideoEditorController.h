//
//  UIVideoEditorController.h
//  UIKit
//
//  Copyright (c) 2009-2017 Apple Inc.. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UINavigationController.h>
#import <UIKit/UIKitDefines.h>
#import <UIKit/UIImagePickerController.h>

NS_ASSUME_NONNULL_BEGIN

@protocol UIVideoEditorControllerDelegate;

NS_CLASS_AVAILABLE_IOS(3_1) __TVOS_PROHIBITED @interface UIVideoEditorController : UINavigationController

+ (BOOL)canEditVideoAtPath:(NSString *)videoPath NS_AVAILABLE_IOS(3_1);

@property(nullable, nonatomic,assign)    id <UINavigationControllerDelegate, UIVideoEditorControllerDelegate> delegate;

@property(nonatomic, copy)     NSString                              *videoPath;
@property(nonatomic)           NSTimeInterval                        videoMaximumDuration; // default value is 10 minutes. set to 0 to specify no maximum duration.
@property(nonatomic)           UIImagePickerControllerQualityType    videoQuality;         // default value is UIImagePickerControllerQualityTypeMedium

@end

__TVOS_PROHIBITED @protocol UIVideoEditorControllerDelegate<NSObject>
@optional
// The editor does not dismiss itself; the client dismisses it in these callbacks.
// The delegate will receive exactly one of the following callbacks, depending whether the user
// confirms or cancels or if the operation fails.
- (void)videoEditorController:(UIVideoEditorController *)editor didSaveEditedVideoToPath:(NSString *)editedVideoPath; // edited video is saved to a path in app's temporary directory
- (void)videoEditorController:(UIVideoEditorController *)editor didFailWithError:(NSError *)error;
- (void)videoEditorControllerDidCancel:(UIVideoEditorController *)editor;

@end

NS_ASSUME_NONNULL_END
