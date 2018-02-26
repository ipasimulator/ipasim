//
//  SFTranscriptionSegment.h
//  Copyright (c) 2016 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Substrings of a hypothesized transcription
API_AVAILABLE(ios(10.0))
@interface SFTranscriptionSegment : NSObject <NSCopying, NSSecureCoding>

@property (nonatomic, readonly, copy) NSString *substring;
@property (nonatomic, readonly) NSRange substringRange;

// Relative to start of utterance
@property (nonatomic, readonly) NSTimeInterval timestamp;
@property (nonatomic, readonly) NSTimeInterval duration;

// Confidence in the accuracy of transcription. Scale is 0 (least confident) to 1.0 (most confident)
@property (nonatomic, readonly) float confidence;

// Other possible interpretations of this segment
@property (nonatomic, readonly) NSArray<NSString *> *alternativeSubstrings;

@end

NS_ASSUME_NONNULL_END
