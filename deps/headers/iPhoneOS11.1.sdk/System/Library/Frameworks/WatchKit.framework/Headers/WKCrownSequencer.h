//
//  WKCrownSequencer.h
//  WatchKit
//
//  Copyright © 2016 Apple Inc. All rights reserved.
//

NS_ASSUME_NONNULL_BEGIN

@protocol WKCrownDelegate;

WK_AVAILABLE_WATCHOS_ONLY(3.0)
@interface WKCrownSequencer : NSObject

@property (nonatomic, weak, nullable) id<WKCrownDelegate> delegate;
@property (nonatomic, readonly) double rotationsPerSecond;
@property (nonatomic, readonly, getter=isIdle) BOOL idle;

- (instancetype)init NS_UNAVAILABLE;
// Sets this sequencer as focused, automatically resigns focus of any WKPickerViews
- (void)focus;
- (void)resignFocus;

@end

WK_AVAILABLE_WATCHOS_ONLY(3.0)
@protocol WKCrownDelegate <NSObject>

@optional
// called when the crown rotates, rotationalDelta is the change since the last call (sign indicates direction).
- (void)crownDidRotate:(nullable WKCrownSequencer *)crownSequencer rotationalDelta:(double)rotationalDelta;
// called when the crown becomes idle
- (void)crownDidBecomeIdle:(nullable WKCrownSequencer *)crownSequencer;

@end

NS_ASSUME_NONNULL_END
