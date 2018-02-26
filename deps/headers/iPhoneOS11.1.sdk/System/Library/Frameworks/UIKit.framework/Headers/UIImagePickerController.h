//
//  UIImagePickerController.h
//  UIKit
//
//  Copyright (c) 2008-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UINavigationController.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class UIImage;
@protocol UIImagePickerControllerDelegate;

typedef NS_ENUM(NSInteger, UIImagePickerControllerSourceType) {
    UIImagePickerControllerSourceTypePhotoLibrary,
    UIImagePickerControllerSourceTypeCamera,
    UIImagePickerControllerSourceTypeSavedPhotosAlbum
} __TVOS_PROHIBITED;

typedef NS_ENUM(NSInteger, UIImagePickerControllerQualityType) {
    UIImagePickerControllerQualityTypeHigh = 0,       // highest quality
    UIImagePickerControllerQualityTypeMedium = 1,     // medium quality, suitable for transmission via Wi-Fi 
    UIImagePickerControllerQualityTypeLow = 2,         // lowest quality, suitable for tranmission via cellular network
    UIImagePickerControllerQualityType640x480 NS_ENUM_AVAILABLE_IOS(4_0) = 3,    // VGA quality
    UIImagePickerControllerQualityTypeIFrame1280x720 NS_ENUM_AVAILABLE_IOS(5_0) = 4,
    UIImagePickerControllerQualityTypeIFrame960x540 NS_ENUM_AVAILABLE_IOS(5_0) = 5,
} __TVOS_PROHIBITED;

typedef NS_ENUM(NSInteger, UIImagePickerControllerCameraCaptureMode) {
    UIImagePickerControllerCameraCaptureModePhoto,
    UIImagePickerControllerCameraCaptureModeVideo
} __TVOS_PROHIBITED;

typedef NS_ENUM(NSInteger, UIImagePickerControllerCameraDevice) {
    UIImagePickerControllerCameraDeviceRear,
    UIImagePickerControllerCameraDeviceFront
} __TVOS_PROHIBITED;

typedef NS_ENUM(NSInteger, UIImagePickerControllerCameraFlashMode) {
    UIImagePickerControllerCameraFlashModeOff  = -1,
    UIImagePickerControllerCameraFlashModeAuto = 0,
    UIImagePickerControllerCameraFlashModeOn   = 1
} __TVOS_PROHIBITED;

typedef NS_ENUM(NSInteger, UIImagePickerControllerImageURLExportPreset) {
    UIImagePickerControllerImageURLExportPresetCompatible = 0,
    UIImagePickerControllerImageURLExportPresetCurrent
} NS_AVAILABLE_IOS(11_0) __TVOS_PROHIBITED;

// info dictionary keys
UIKIT_EXTERN NSString *const UIImagePickerControllerMediaType __TVOS_PROHIBITED;      // an NSString (UTI, i.e. kUTTypeImage)
UIKIT_EXTERN NSString *const UIImagePickerControllerOriginalImage __TVOS_PROHIBITED;  // a UIImage
UIKIT_EXTERN NSString *const UIImagePickerControllerEditedImage __TVOS_PROHIBITED;    // a UIImage
UIKIT_EXTERN NSString *const UIImagePickerControllerCropRect __TVOS_PROHIBITED;       // an NSValue (CGRect)
UIKIT_EXTERN NSString *const UIImagePickerControllerMediaURL __TVOS_PROHIBITED;       // an NSURL
UIKIT_EXTERN NSString *const UIImagePickerControllerReferenceURL        NS_DEPRECATED_IOS(4_1, 11_0, "Replace with public API: UIImagePickerControllerPHAsset") __TVOS_PROHIBITED;  // an NSURL that references an asset in the AssetsLibrary framework
UIKIT_EXTERN NSString *const UIImagePickerControllerMediaMetadata       NS_AVAILABLE_IOS(4_1) __TVOS_PROHIBITED;  // an NSDictionary containing metadata from a captured photo
UIKIT_EXTERN NSString *const UIImagePickerControllerLivePhoto NS_AVAILABLE_IOS(9_1) __TVOS_PROHIBITED;  // a PHLivePhoto
UIKIT_EXTERN NSString *const UIImagePickerControllerPHAsset NS_AVAILABLE_IOS(11_0) __TVOS_PROHIBITED;  // a PHAsset
UIKIT_EXTERN NSString *const UIImagePickerControllerImageURL NS_AVAILABLE_IOS(11_0) __TVOS_PROHIBITED;  // an NSURL

NS_CLASS_AVAILABLE_IOS(2_0) __TVOS_PROHIBITED @interface UIImagePickerController : UINavigationController <NSCoding>

+ (BOOL)isSourceTypeAvailable:(UIImagePickerControllerSourceType)sourceType;                 // returns YES if source is available (i.e. camera present)
+ (nullable NSArray<NSString *> *)availableMediaTypesForSourceType:(UIImagePickerControllerSourceType)sourceType; // returns array of available media types (i.e. kUTTypeImage)

+ (BOOL)isCameraDeviceAvailable:(UIImagePickerControllerCameraDevice)cameraDevice                   NS_AVAILABLE_IOS(4_0); // returns YES if camera device is available 
+ (BOOL)isFlashAvailableForCameraDevice:(UIImagePickerControllerCameraDevice)cameraDevice           NS_AVAILABLE_IOS(4_0); // returns YES if camera device supports flash and torch.
+ (nullable NSArray<NSNumber *> *)availableCaptureModesForCameraDevice:(UIImagePickerControllerCameraDevice)cameraDevice NS_AVAILABLE_IOS(4_0); // returns array of NSNumbers (UIImagePickerControllerCameraCaptureMode)

@property(nullable,nonatomic,weak)      id <UINavigationControllerDelegate, UIImagePickerControllerDelegate> delegate;

@property(nonatomic)           UIImagePickerControllerSourceType     sourceType;                                                        // default value is UIImagePickerControllerSourceTypePhotoLibrary.
@property(nonatomic,copy)      NSArray<NSString *>                   *mediaTypes;
    // default value is an array containing kUTTypeImage.
@property(nonatomic)           BOOL                                  allowsEditing NS_AVAILABLE_IOS(3_1);     // replacement for -allowsImageEditing; default value is NO.
@property(nonatomic)           BOOL                                  allowsImageEditing NS_DEPRECATED_IOS(2_0, 3_1);
@property(nonatomic)           UIImagePickerControllerImageURLExportPreset imageExportPreset NS_AVAILABLE_IOS(11_0);   // default value is UIImagePickerControllerImageExportPresetCompatible.

// video properties apply only if mediaTypes includes kUTTypeMovie
@property(nonatomic)           NSTimeInterval                        videoMaximumDuration NS_AVAILABLE_IOS(3_1); // default value is 10 minutes.
@property(nonatomic)           UIImagePickerControllerQualityType    videoQuality NS_AVAILABLE_IOS(3_1);         // default value is UIImagePickerControllerQualityTypeMedium. If the cameraDevice does not support the videoQuality, it will use the default value.
@property(nonatomic, copy)     NSString                              *videoExportPreset NS_AVAILABLE_IOS(11_0);  // videoExportPreset can be used to specify the transcoding quality for videos (via a AVAssetExportPreset* string). If the value is nil (the default) then the transcodeQuality is determined by videoQuality instead. Not valid if the source type is UIImagePickerControllerSourceTypeCamera


// camera additions available only if sourceType is UIImagePickerControllerSourceTypeCamera.
@property(nonatomic)           BOOL                                  showsCameraControls NS_AVAILABLE_IOS(3_1);   // set to NO to hide all standard camera UI. default is YES
@property(nullable, nonatomic,strong) __kindof UIView                *cameraOverlayView  NS_AVAILABLE_IOS(3_1);   // set a view to overlay the preview view.
@property(nonatomic)           CGAffineTransform                     cameraViewTransform NS_AVAILABLE_IOS(3_1);   // set the transform of the preview view.

- (void)takePicture NS_AVAILABLE_IOS(3_1);                                                   
// programatically initiates still image capture. ignored if image capture is in-flight.
// clients can initiate additional captures after receiving -imagePickerController:didFinishPickingMediaWithInfo: delegate callback

- (BOOL)startVideoCapture NS_AVAILABLE_IOS(4_0);
- (void)stopVideoCapture  NS_AVAILABLE_IOS(4_0);

@property(nonatomic) UIImagePickerControllerCameraCaptureMode cameraCaptureMode NS_AVAILABLE_IOS(4_0); // default is UIImagePickerControllerCameraCaptureModePhoto
@property(nonatomic) UIImagePickerControllerCameraDevice      cameraDevice      NS_AVAILABLE_IOS(4_0); // default is UIImagePickerControllerCameraDeviceRear
@property(nonatomic) UIImagePickerControllerCameraFlashMode   cameraFlashMode   NS_AVAILABLE_IOS(4_0); // default is UIImagePickerControllerCameraFlashModeAuto. 
// cameraFlashMode controls the still-image flash when cameraCaptureMode is Photo. cameraFlashMode controls the video torch when cameraCaptureMode is Video.

@end

__TVOS_PROHIBITED @protocol UIImagePickerControllerDelegate<NSObject>
@optional
// The picker does not dismiss itself; the client dismisses it in these callbacks.
// The delegate will receive one or the other, but not both, depending whether the user
// confirms or cancels.
- (void)imagePickerController:(UIImagePickerController *)picker didFinishPickingImage:(UIImage *)image editingInfo:(nullable NSDictionary<NSString *,id> *)editingInfo NS_DEPRECATED_IOS(2_0, 3_0);
- (void)imagePickerController:(UIImagePickerController *)picker didFinishPickingMediaWithInfo:(NSDictionary<NSString *,id> *)info;
- (void)imagePickerControllerDidCancel:(UIImagePickerController *)picker;

@end


// Adds a photo to the saved photos album.  The optional completionSelector should have the form:
//  - (void)image:(UIImage *)image didFinishSavingWithError:(NSError *)error contextInfo:(void *)contextInfo;
UIKIT_EXTERN void UIImageWriteToSavedPhotosAlbum(UIImage *image, __nullable id completionTarget, __nullable SEL completionSelector, void * __nullable contextInfo) __TVOS_PROHIBITED;

// Is a specific video eligible to be saved to the saved photos album? 
UIKIT_EXTERN BOOL UIVideoAtPathIsCompatibleWithSavedPhotosAlbum(NSString *videoPath) NS_AVAILABLE_IOS(3_1) __TVOS_PROHIBITED;

// Adds a video to the saved photos album. The optional completionSelector should have the form:
//  - (void)video:(NSString *)videoPath didFinishSavingWithError:(NSError *)error contextInfo:(void *)contextInfo;
UIKIT_EXTERN void UISaveVideoAtPathToSavedPhotosAlbum(NSString *videoPath, __nullable id completionTarget, __nullable SEL completionSelector, void * __nullable contextInfo) NS_AVAILABLE_IOS(3_1) __TVOS_PROHIBITED;

NS_ASSUME_NONNULL_END
