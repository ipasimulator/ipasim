//
//  CustomLayer.h
//  SampleGame
//
//  Created by Jan Jones on 5/25/19.
//  Copyright © 2019 Jan Jones. All rights reserved.
//

#import <QuartzCore/QuartzCore.h>

@interface CALayer (CustomLayer)

- (CALayer *)createSublayer:(Class)type;
- (void)updateFrame:(CGRect)frame;

@end

@interface CustomLayer : CALayer <CALayerDelegate>

- (void)draw;

@end

@interface CircleLayer : CustomLayer
@end

@interface FloorLayer : CustomLayer
@end

@interface EnemyLayer : CustomLayer
@end
