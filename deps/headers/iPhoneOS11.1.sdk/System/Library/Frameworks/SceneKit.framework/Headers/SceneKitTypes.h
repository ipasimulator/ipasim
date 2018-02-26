//
//  SceneKitTypes.h
//
//  Copyright (c) 2012-2017 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <simd/simd.h>

#import <QuartzCore/QuartzCore.h>
#import <GLKit/GLKMathTypes.h>

/*! @header SceneKitTypes
 @abstract Various types and utility functions used throughout SceneKit
 */

#define SCN_ENABLE_METAL (!TARGET_OS_SIMULATOR)

#if SCN_ENABLE_METAL
#import <Metal/Metal.h>
#endif


// Color
#define SCNColor UIColor

/*! @enum SCNActionTimingMode
 @abstract The modes that an action can use to adjust the apparent timing of the action.
 */
typedef NS_ENUM(NSInteger, SCNActionTimingMode) {
    SCNActionTimingModeLinear,
    SCNActionTimingModeEaseIn,
    SCNActionTimingModeEaseOut,
    SCNActionTimingModeEaseInEaseOut
} API_AVAILABLE(macos(10.10), ios(8.0));

/*! @enum SCNColorComponent
 @abstract Color components
 */
typedef NS_OPTIONS(NSInteger, SCNColorMask) {
    SCNColorMaskNone   = 0,
    SCNColorMaskRed    = 0x1 << 3,
    SCNColorMaskGreen  = 0x1 << 2,
    SCNColorMaskBlue   = 0x1 << 1,
    SCNColorMaskAlpha  = 0x1 << 0,
    SCNColorMaskAll    = 0xf
} API_AVAILABLE(macos(10.13), ios(11.0), tvos(11.0), watchos(4.0));

#pragma mark - Vectors

typedef struct SCNVector3 {
    float x, y, z;
} SCNVector3;

typedef struct SCNVector4 {
    float x, y, z, w;
} SCNVector4;

/* The null vector: [0 0 0]. */
FOUNDATION_EXTERN const SCNVector3 SCNVector3Zero API_AVAILABLE(macos(10.10));

/* The null vector: [0 0 0 0]. */
FOUNDATION_EXTERN const SCNVector4 SCNVector4Zero API_AVAILABLE(macos(10.10));

/* Returns true if 'a' is exactly equal to 'b'. */
FOUNDATION_EXTERN bool SCNVector3EqualToVector3 (SCNVector3 a, SCNVector3 b);

/* Returns true if 'a' is exactly equal to 'b'. */
FOUNDATION_EXTERN bool SCNVector4EqualToVector4 (SCNVector4 a, SCNVector4 b);

/* Returns an initialized SCNVector3 */
NS_INLINE SCNVector3 SCNVector3Make(float x, float y, float z) {
    SCNVector3 v = {x, y, z};
    return v;
}

/* Returns an initialized SCNVector4 */
NS_INLINE SCNVector4 SCNVector4Make(float x, float y, float z, float w) {
    SCNVector4 v = {x, y, z, w};
    return v;
}


#pragma mark - Quaternions

typedef SCNVector4 SCNQuaternion;


#pragma mark - Matrices

typedef struct SCNMatrix4 {
    float m11, m12, m13, m14;
    float m21, m22, m23, m24;
    float m31, m32, m33, m34;
    float m41, m42, m43, m44;
} SCNMatrix4;

/* The identity matrix: [1 0 0 0; 0 1 0 0; 0 0 1 0; 0 0 0 1]. */
FOUNDATION_EXTERN const SCNMatrix4 SCNMatrix4Identity API_AVAILABLE(macos(10.10));

/* Returns true if 'm' is the identity matrix. */
FOUNDATION_EXTERN bool SCNMatrix4IsIdentity(SCNMatrix4 m) API_AVAILABLE(macos(10.10));

/* Returns true if 'a' is exactly equal to 'b'. */
FOUNDATION_EXTERN bool SCNMatrix4EqualToMatrix4(SCNMatrix4 a, SCNMatrix4 b) API_AVAILABLE(macos(10.10));

/* Returns a transform that translates by '(tx, ty, tz)':
 * m' =  [1 0 0 0; 0 1 0 0; 0 0 1 0; tx ty tz 1]. */
NS_INLINE SCNMatrix4 SCNMatrix4MakeTranslation(float tx, float ty, float tz) {
    SCNMatrix4 m = SCNMatrix4Identity;
    m.m41 = tx;
    m.m42 = ty;
    m.m43 = tz;
    return m;
}

/* Returns a transform that scales by '(sx, sy, sz)':
 * m' = [sx 0 0 0; 0 sy 0 0; 0 0 sz 0; 0 0 0 1]. */
NS_INLINE SCNMatrix4 SCNMatrix4MakeScale(float sx, float sy, float sz) {
    SCNMatrix4 m = SCNMatrix4Identity;
    m.m11 = sx;
    m.m22 = sy;
    m.m33 = sz;
    return m;
}

/* Returns a matrix that rotates by 'angle' radians about the vector '(x, y, z)'. */
FOUNDATION_EXTERN SCNMatrix4 SCNMatrix4MakeRotation(float angle, float x, float y, float z) API_AVAILABLE(macos(10.10));

/* Translate 'm' by '(tx, ty, tz)' and return the result:
 * m' = translate(tx, ty, tz) * m. */
NS_INLINE SCNMatrix4 SCNMatrix4Translate(SCNMatrix4 m, float tx, float ty, float tz) {
    m.m41 += tx;
    m.m42 += ty;
    m.m43 += tz;
    return m;
}

/* Scale 'm' by '(sx, sy, sz)' and return the result:
 * m' = scale(sx, sy, sz) * m. */
FOUNDATION_EXTERN SCNMatrix4 SCNMatrix4Scale(SCNMatrix4 m, float sx, float sy, float sz) API_AVAILABLE(macos(10.10));

/* Rotate 'm' by 'angle' radians about the vector '(x, y, z)' and return the result:
 * m' = rotation(angle, x, y, z) * m. */
FOUNDATION_EXTERN SCNMatrix4 SCNMatrix4Rotate(SCNMatrix4 m, float angle, float x, float y, float z) API_AVAILABLE(macos(10.10));

/* Invert 'm' and return the result. */
FOUNDATION_EXTERN SCNMatrix4 SCNMatrix4Invert(SCNMatrix4 m) API_AVAILABLE(macos(10.10));

/* Concatenate 'b' to 'a' and return the result: m' = a * b. */
FOUNDATION_EXTERN SCNMatrix4 SCNMatrix4Mult(SCNMatrix4 a, SCNMatrix4 b) API_AVAILABLE(macos(10.10));


#pragma mark - GLKit Bridge

NS_INLINE SCNVector3 SCNVector3FromGLKVector3(GLKVector3 vector) {
    SCNVector3 v = (SCNVector3){vector.v[0], vector.v[1], vector.v[2]};
    return v;
}

NS_INLINE GLKVector3 SCNVector3ToGLKVector3(SCNVector3 vector) {
    GLKVector3 v = {{(float)vector.x, (float)vector.y, (float)vector.z}};
    return v;
}

NS_INLINE SCNVector4 SCNVector4FromGLKVector4(GLKVector4 vector) {
    SCNVector4 v = (SCNVector4){vector.v[0], vector.v[1], vector.v[2], vector.v[3]};
    return v;
}

NS_INLINE GLKVector4 SCNVector4ToGLKVector4(SCNVector4 vector) {
    GLKVector4 v = {{vector.x, vector.y, vector.z, vector.w}};
    return v;
}

FOUNDATION_EXTERN GLKMatrix4 SCNMatrix4ToGLKMatrix4(SCNMatrix4 mat) API_AVAILABLE(macos(10.10));
FOUNDATION_EXTERN SCNMatrix4 SCNMatrix4FromGLKMatrix4(GLKMatrix4 mat) API_AVAILABLE(macos(10.10));


#pragma mark - SIMD Bridge
    
NS_INLINE vector_float3 SCNVector3ToFloat3(SCNVector3 v) {
    vector_float3 vec = {(float)v.x, (float)v.y, (float)v.z};
    return vec;
}

NS_INLINE vector_float4 SCNVector4ToFloat4(SCNVector4 v) {
    vector_float4 vec = {(float)v.x, (float)v.y, (float)v.z, (float)v.w};
    return vec;
}

NS_INLINE matrix_float4x4 SCNMatrix4ToMat4(SCNMatrix4 m) {
    matrix_float4x4 mat;
    mat.columns[0] = (vector_float4){(float)m.m11, (float)m.m12, (float)m.m13, (float)m.m14};
    mat.columns[1] = (vector_float4){(float)m.m21, (float)m.m22, (float)m.m23, (float)m.m24};
    mat.columns[2] = (vector_float4){(float)m.m31, (float)m.m32, (float)m.m33, (float)m.m34};
    mat.columns[3] = (vector_float4){(float)m.m41, (float)m.m42, (float)m.m43, (float)m.m44};
    return mat;
}

NS_INLINE SCNVector3 SCNVector3FromFloat3(vector_float3 v) {
    SCNVector3 vec = {v.x, v.y, v.z } ;
    return vec;
}

NS_INLINE SCNVector4 SCNVector4FromFloat4(vector_float4 v) {
    SCNVector4 vec = {v.x, v.y, v.z, v.w } ;
    return vec;
}

NS_INLINE SCNMatrix4 SCNMatrix4FromMat4(matrix_float4x4 m) {
    SCNMatrix4 mat;
    memcpy(&mat, &m, sizeof(mat));
    return mat;
}


#pragma mark - NSValue Additions
    
#ifdef __OBJC__
    
NS_ASSUME_NONNULL_BEGIN

/*! @category NSValue(SceneKitAdditions)
 @abstract Adds methods to wrap vectors in NSValue objects.
 */

@interface NSValue (SceneKitAdditions)

+ (NSValue *)valueWithSCNVector3:(SCNVector3)v;
+ (NSValue *)valueWithSCNVector4:(SCNVector4)v;
+ (NSValue *)valueWithSCNMatrix4:(SCNMatrix4)v API_AVAILABLE(macos(10.10));

@property(nonatomic, readonly) SCNVector3 SCNVector3Value;
@property(nonatomic, readonly) SCNVector4 SCNVector4Value;
@property(nonatomic, readonly) SCNMatrix4 SCNMatrix4Value API_AVAILABLE(macos(10.10));

@end


#pragma mark - Errors

//domain for errors from SceneKit API.
FOUNDATION_EXTERN NSString * const SCNErrorDomain;

// NSError codes in SCNErrorDomain.
enum {
	SCNProgramCompilationError = 1
};

NS_ASSUME_NONNULL_END
    
#endif /* __OBJC__ */
