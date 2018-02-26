/* CoreAnimation - CAEAGLLayer.h

   Copyright (c) 2007-2017, Apple Inc.
   All rights reserved. */

#import <QuartzCore/CALayer.h>
#import <OpenGLES/EAGLDrawable.h>

NS_ASSUME_NONNULL_BEGIN

/* CAEAGLLayer is a layer that implements the EAGLDrawable protocol,
 * allowing it to be used as an OpenGLES render target. Use the
 * `drawableProperties' property defined by the protocol to configure
 * the created surface. */

CA_CLASS_AVAILABLE_IOS(2.0, 9.0, 2.0)
@interface CAEAGLLayer : CALayer <EAGLDrawable>
{
@private
  struct _CAEAGLNativeWindow *_win;
}

/* When false (the default value) changes to the layer's render buffer
 * appear on-screen asynchronously to normal layer updates. When true,
 * changes to the GLES content are sent to the screen via the standard
 * CATransaction mechanisms. */

@property BOOL presentsWithTransaction CA_AVAILABLE_IOS_STARTING (9.0, 9.0, 2.0);

/* Note: the default value of the `opaque' property in this class is true,
 * not false as in CALayer. */

@end

NS_ASSUME_NONNULL_END
