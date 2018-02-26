//
//  UIPrintInteractionController.h
//  UIKit
//
//  Copyright 2010-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <UIKit/UIApplication.h>
#import <UIKit/UIKitDefines.h>

NS_ASSUME_NONNULL_BEGIN

@class UIPrintInteractionController, UIPrintInfo, UIPrintPaper, UIPrintPageRenderer, UIPrintFormatter, UIPrinter;
@class UIView, UIBarButtonItem;

typedef void (^UIPrintInteractionCompletionHandler)(UIPrintInteractionController *printInteractionController, BOOL completed, NSError * __nullable error) __TVOS_PROHIBITED;


NS_ENUM_AVAILABLE_IOS(9_0) typedef NS_ENUM(NSInteger, UIPrinterCutterBehavior) {
    UIPrinterCutterBehaviorNoCut,
    UIPrinterCutterBehaviorPrinterDefault,
    UIPrinterCutterBehaviorCutAfterEachPage,
    UIPrinterCutterBehaviorCutAfterEachCopy,
    UIPrinterCutterBehaviorCutAfterEachJob,
} __TVOS_PROHIBITED;

@protocol UIPrintInteractionControllerDelegate;

NS_CLASS_AVAILABLE_IOS(4_2) __TVOS_PROHIBITED @interface UIPrintInteractionController : NSObject

#if UIKIT_DEFINE_AS_PROPERTIES
@property(class, nonatomic, readonly, getter=isPrintingAvailable) BOOL printingAvailable;                    // return YES if system supports printing. use this to hide HI for unsupported devices.
#else
+ (BOOL)isPrintingAvailable;                    // return YES if system supports printing. use this to hide HI for unsupported devices.
#endif

#if UIKIT_DEFINE_AS_PROPERTIES
@property(class, nonatomic, readonly) NSSet<NSString *> *printableUTIs;                       // return set of all document UTI types we can print
#else
+ (NSSet<NSString *> *)printableUTIs;                       // return set of all document UTI types we can print
#endif
+ (BOOL)canPrintURL:(NSURL *)url;
+ (BOOL)canPrintData:(NSData *)data;

#if UIKIT_DEFINE_AS_PROPERTIES
@property(class, nonatomic, readonly) UIPrintInteractionController *sharedPrintController;
#else
+ (UIPrintInteractionController *)sharedPrintController;
#endif

@property(nullable,nonatomic,strong) UIPrintInfo                             *printInfo;      // changes to printInfo ignored while printing. default is nil
@property(nullable,nonatomic,weak)   id<UIPrintInteractionControllerDelegate> delegate;       // not retained. default is nil
@property(nonatomic)        BOOL                                     showsPageRange NS_DEPRECATED_IOS(4_2,10_0, "Pages can be removed from the print preview, so page range is always shown.");
@property(nonatomic)        BOOL                                     showsNumberOfCopies NS_AVAILABLE_IOS(7_0); // default is YES.
@property(nonatomic)        BOOL                                     showsPaperSelectionForLoadedPapers NS_AVAILABLE_IOS(8_0); // default is NO.  Paper selection for loaded papers is always shown for UIPrintInfoOutputPhoto and UIPrintInfoOutputPhotoGrayscale

@property(nullable, nonatomic,readonly) UIPrintPaper *printPaper;  // set after printer selection

@property(nullable,nonatomic,strong) UIPrintPageRenderer *printPageRenderer;  // calls class to render each page
@property(nullable,nonatomic,strong) UIPrintFormatter    *printFormatter;     // uses a single formatter to fill the pages
@property(nullable,nonatomic,copy)   id                   printingItem;       // single NSData, NSURL, UIImage, ALAsset
@property(nullable,nonatomic,copy)   NSArray             *printingItems;      // array of NSData, NSURL, UIImage, ALAsset. does not support page range

- (BOOL)presentAnimated:(BOOL)animated completionHandler:(nullable UIPrintInteractionCompletionHandler)completion;                                                // iPhone
- (BOOL)presentFromRect:(CGRect)rect inView:(UIView *)view animated:(BOOL)animated completionHandler:(nullable UIPrintInteractionCompletionHandler)completion;    // iPad
- (BOOL)presentFromBarButtonItem:(UIBarButtonItem *)item animated:(BOOL)animated completionHandler:(nullable UIPrintInteractionCompletionHandler)completion;      // iPad

/*!
 * @discussion	Use to print without showing the standard print panel. Use with a
 *		UIPrinter found using the UIPrinterPickerController.
 *              The value for the duplex property on printInfo will be ignored.
 */
- (BOOL)printToPrinter:(UIPrinter *)printer completionHandler:(nullable UIPrintInteractionCompletionHandler)completion;

- (void)dismissAnimated:(BOOL)animated;

@end

__TVOS_PROHIBITED @protocol UIPrintInteractionControllerDelegate <NSObject>
@optional

- ( UIViewController * _Nullable )printInteractionControllerParentViewController:(UIPrintInteractionController *)printInteractionController;

- (UIPrintPaper *)printInteractionController:(UIPrintInteractionController *)printInteractionController choosePaper:(NSArray<UIPrintPaper *> *)paperList;

- (void)printInteractionControllerWillPresentPrinterOptions:(UIPrintInteractionController *)printInteractionController;
- (void)printInteractionControllerDidPresentPrinterOptions:(UIPrintInteractionController *)printInteractionController;
- (void)printInteractionControllerWillDismissPrinterOptions:(UIPrintInteractionController *)printInteractionController;
- (void)printInteractionControllerDidDismissPrinterOptions:(UIPrintInteractionController *)printInteractionController;

- (void)printInteractionControllerWillStartJob:(UIPrintInteractionController *)printInteractionController;
- (void)printInteractionControllerDidFinishJob:(UIPrintInteractionController *)printInteractionController;

- (CGFloat)printInteractionController:(UIPrintInteractionController *)printInteractionController cutLengthForPaper:(UIPrintPaper *)paper NS_AVAILABLE_IOS(7_0);
- (UIPrinterCutterBehavior) printInteractionController:(UIPrintInteractionController *)printInteractionController chooseCutterBehavior:(NSArray *)availableBehaviors NS_AVAILABLE_IOS(9_0);

@end

NS_ASSUME_NONNULL_END
