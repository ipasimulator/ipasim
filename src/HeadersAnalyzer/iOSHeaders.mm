
// See <objc/objc-api.h>.
#define OBJC_OLD_DISPATCH_PROTOTYPES 0

#if !defined(IPASIM_CG_SAMPLE)
#include <objc/NSObject.h>
#include <objc/message.h>
#include <objc/objc.h>
#include <objc/runtime.h>
#include <objc-abi.h>
#include <objc-internal.h>
#include <Accelerate/Accelerate.h>
#include <Accounts/Accounts.h>
#include <AddressBook/AddressBook.h>
#include <AddressBookUI/AddressBookUI.h>
#include <AdSupport/AdSupport.h>
#include <AssetsLibrary/AssetsLibrary.h>
#include <AudioToolbox/AudioToolbox.h>
#include <AudioUnit/AudioUnit.h>
#include <AVFoundation/AVFoundation.h>
#include <AVKit/AVKit.h>
#include <CFNetwork/CFNetwork.h>
#include <CloudKit/CloudKit.h>
#include <Contacts/Contacts.h>
#include <CoreAudio/CoreAudioTypes.h>
#include <CoreAudioKit/CoreAudioKit.h>
#include <CoreBluetooth/CoreBluetooth.h>
#include <CoreData/CoreData.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreImage/CoreImage.h>
#include <CoreLocation/CoreLocation.h>
#include <CoreMedia/CoreMedia.h>
#include <CoreMIDI/CoreMIDI.h>
#include <CoreMotion/CoreMotion.h>
#include <CoreTelephony/CoreTelephonyDefines.h>
#include <CoreTelephony/CTCall.h>
#include <CoreTelephony/CTCallCenter.h>
#include <CoreTelephony/CTCarrier.h>
#include <CoreTelephony/CTCellularData.h>
#include <CoreTelephony/CTSubscriber.h>
#include <CoreTelephony/CTSubscriberInfo.h>
#include <CoreTelephony/CTTelephonyNetworkInfo.h>
#include <CoreText/CoreText.h>
#include <CoreVideo/CoreVideo.h>
#include <EventKit/EventKit.h>
#include <EventKitUI/EventKitUI.h>
#include <Foundation/Foundation.h>
#include <GameController/GameController.h>
#include <GameKit/GameKit.h>
#include <GamePlayKit/GamePlayKit.h>
#include <GLKit/GLKit.h>
#include <HealthKit/HealthKit.h>
#include <HomeKit/HomeKit.h>
#include <iAd/iAd.h>
#include <ImageIO/ImageIO.h>
#include <LocalAuthentication/LocalAuthentication.h>
#include <MapKit/MapKit.h>
#include <MediaAccessibility/MediaAccessibility.h>
#include <MediaPlayer/MediaPlayer.h>
#include <MessageUI/MessageUI.h>
#include <Metal/Metal.h>
#include <MobileCoreServices/MobileCoreServices.h>
#include <OpenGLES/EAGL.h>
#include <OpenGLES/EAGLDrawable.h>
#include <OpenGLES/EAGLIOSurface.h>
#include <OpenGLES/gltypes.h>
#include <OpenGLES/ES2/gl.h>
#include <OpenGLES/ES2/glext.h>
#endif
#include <QuartzCore/QuartzCore.h>
#if !defined(IPASIM_CG_SAMPLE)
#include <QuickLook/QuickLook.h>
#include <SafariServices/SafariServices.h>
#include <Security/Security.h>
#include <Social/Social.h>
#include <StoreKit/StoreKit.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <Twitter/Twitter.h>
#include <UIKit/UIKit.h>
#include <WebKit/WebKit.h>

// These don't have C declarations anywhere, since they're only used in
// assembly, but we want to have wrappers generated for them, too.
OBJC_EXPORT void _objc_msgNil(void /* id self, SEL op, ... */);
OBJC_EXPORT void _objc_msgNil_stret(void /* id self, SEL op, ... */);
OBJC_EXPORT void _objc_msgNil_fpret(void /* id self, SEL op, ... */);
OBJC_EXPORT void objc_msgLookupSuper(void);
OBJC_EXPORT void objc_msgLookupSuper_stret(void);
#endif
