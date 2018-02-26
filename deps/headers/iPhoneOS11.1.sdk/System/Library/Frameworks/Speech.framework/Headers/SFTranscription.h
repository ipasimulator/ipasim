//
//  SFTranscription.h
//  Copyright (c) 2016 Apple Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class SFTranscriptionSegment;

// A hypothesized text form of a speech recording
API_AVAILABLE(ios(10.0))
@interface SFTranscription : NSObject <NSCopying, NSSecureCoding>

// Contains the entire recognition, formatted into a single user-displayable string
@property (nonatomic, readonly, copy) NSString *formattedString;

@property (nonatomic, readonly, copy) NSArray<SFTranscriptionSegment *> *segments;

@end

NS_ASSUME_NONNULL_END
