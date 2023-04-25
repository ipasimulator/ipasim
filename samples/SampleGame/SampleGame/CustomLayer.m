//
//  CustomLayer.m
//  SampleGame
//
//  Created by Jan Jones on 5/25/19.
//  Copyright © 2019 Jan Jones. All rights reserved.
//

#import "CustomLayer.h"

#import <UIKit/UIKit.h>

@implementation CustomLayer

- (void)drawLayer:(CALayer *)layer inContext:(CGContextRef)ctx {
    UIGraphicsPushContext(ctx);
    [self draw];
    UIGraphicsPopContext();
}

- (void)draw {}

@end

@implementation CALayer (CustomLayer)

- (CALayer *)createSublayer:(Class)type {
    CALayer <CALayerDelegate> *layer = [type layer];
    layer.delegate = layer;
    [self addSublayer:layer];
    return layer;
}

- (void)updateFrame:(CGRect)frame {
    self.frame = frame;
    [self setNeedsDisplay];
}

@end

@implementation CircleLayer

- (void)draw {
    CGRect rect = self.bounds;
    CGPoint center = CGPointMake(rect.size.width / 2.0, rect.size.height / 2.0);
    UIBezierPath *circle = [UIBezierPath bezierPathWithArcCenter:center radius:rect.size.height / 2.0 startAngle:0.0 endAngle:2*M_PI clockwise:YES];
    [[UIColor redColor] setFill];
    [circle fill];
}

@end

@implementation FloorLayer

- (void)draw {
    UIBezierPath *rect = [UIBezierPath bezierPathWithRect:self.bounds];
    [[UIColor blackColor] setFill];
    [rect fill];
}

@end

@implementation EnemyLayer

- (void)draw {
    UIBezierPath *rect = [UIBezierPath bezierPathWithRect:self.bounds];
    [[UIColor blueColor] setFill];
    [rect fill];
}

@end
