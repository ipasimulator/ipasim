//
//  ViewController.m
//  SampleGame
//
//  Created by Jan Jones on 5/24/19.
//  Copyright © 2019 Jan Jones. All rights reserved.
//

#import "ViewController.h"

#import "CustomLayer.h"

// Config
const CGFloat floorHeight = 5.0;
const CGFloat floorMarginBottom = 10.0;
const CGFloat circRadius = 10.0;
const CGFloat enemySize = 20.0;
const CGFloat minEnemyDuration = 1.0;
const int deltaEnemyDuration = 2;
const CGFloat jumpHeight = 100.0;
const CGFloat jumpDuration = 1.0;

static CGPoint center(CGRect rect) {
    return CGPointMake(rect.origin.x + rect.size.width / 2.0, rect.origin.y + rect.size.height / 2.0);
}

@interface AnimationDelegate : NSObject <CAAnimationDelegate> {
    void (^block)(void);
}

+ (instancetype)onEnd:(void (^)(void))block;

@end

@implementation AnimationDelegate

+ (instancetype)onEnd:(void (^)(void))block {
    AnimationDelegate *instance = [[AnimationDelegate alloc] init];
    instance->block = block;
    return instance;
}

- (void)animationDidStop:(CAAnimation *)anim finished:(BOOL)flag {
    if (!flag)
        return;
    
    block();
}

@end

@interface ViewController () {
    UILabel *goLabel;
    CALayer *floorLayer, *circLayer, *enemyLayer;
    BOOL canJump, gameOver, canRestart;
    int enemyState; // 0 - beginning, 1 - half, 2 - left, 3 - half back
}

@end

@implementation ViewController

- (void)viewDidLoad {
    gameOver = NO;
    goLabel = [[UILabel alloc] init];
    goLabel.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:goLabel];
    
    floorLayer = [self.view.layer createSublayer:[FloorLayer class]];
    circLayer = [self.view.layer createSublayer:[CircleLayer class]];
    enemyLayer = [self.view.layer createSublayer:[EnemyLayer class]];
    canJump = YES;
}

- (void)viewWillLayoutSubviews {
    // Screen
    CGRect rect = self.view.layer.bounds;
    
    // Floor
    CGRect floor = CGRectMake(0.0, rect.size.height - floorHeight - floorMarginBottom, rect.size.width, floorHeight);
    [floorLayer updateFrame:floor];
    
    // Circle
    CGFloat circDiam = 2.0 * circRadius;
    CGRect circ = CGRectMake(floor.origin.x + floor.size.width / 2.0 - circRadius, floor.origin.y - circDiam, circDiam, circDiam);
    [circLayer updateFrame:circ];
    
    // Enemy
    CGRect enemy = CGRectMake(floor.origin.x + floor.size.width - enemySize, floor.origin.y - enemySize, enemySize, enemySize);
    [enemyLayer updateFrame:enemy];
    
    // Game over label
    CGRect label = CGRectMake(0.0, floor.origin.y - jumpHeight, rect.size.width, 30.0);
    goLabel.frame = label;
    
    enemyState = 0;
    if (!gameOver)
        [self moveEnemy];
}

- (void)jump {
    // Circle animation
    CGPoint circPos = center(circLayer.frame);
    CABasicAnimation *circAnim = [CABasicAnimation animationWithKeyPath:@"position"];
    circAnim.fromValue = [NSValue valueWithCGPoint:circPos];
    circAnim.toValue = [NSValue valueWithCGPoint:CGPointMake(circPos.x, circPos.y - jumpHeight)];
    circAnim.duration = jumpDuration;
    circAnim.autoreverses = YES;
    circAnim.timingFunction = [CAMediaTimingFunction functionWithName:kCAMediaTimingFunctionEaseOut];
    circAnim.delegate = [AnimationDelegate onEnd:^{
        self->canJump = YES;
    }];
    [circLayer addAnimation:circAnim forKey:@"CircAnim"];
    canJump = NO;
}

- (void)setCanRestart {
    canRestart = YES;
}

- (void)moveEnemyInRunLoop {
    NSTimer *timer = [NSTimer scheduledTimerWithTimeInterval:0.0 target:self selector:@selector(moveEnemy) userInfo:nil repeats:NO];
    [[NSRunLoop currentRunLoop] addTimer:timer forMode:NSDefaultRunLoopMode];
}

- (void)moveEnemy {
    // Collision detection
    if (enemyState % 2 == 1 && canJump) {
        canJump = NO;
        gameOver = YES;
        canRestart = NO;
        goLabel.text = @"Game over";
        NSTimer *timer = [NSTimer scheduledTimerWithTimeInterval:0.1 target:goLabel selector:@selector(setNeedsDisplay) userInfo:nil repeats:NO];
        [[NSRunLoop currentRunLoop] addTimer:timer forMode:NSDefaultRunLoopMode];
        timer = [NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(setCanRestart) userInfo:nil repeats:NO];
        [[NSRunLoop currentRunLoop] addTimer:timer forMode:NSDefaultRunLoopMode];
        return;
    }
    
    // Enemy animation
    CGRect floor = floorLayer.frame;
    CGFloat enemyReach = (floor.size.width - enemySize) / 2.0;
    CGPoint enemyPos = center(enemyLayer.frame);
    CGFloat enemySource;
    switch (enemyState) {
        case 0: enemySource = enemyPos.x; break;
        case 1: case 3: enemySource = enemyPos.x - enemyReach; break;
        case 2: enemySource = enemyPos.x - 2.0 * enemyReach; break;
        default: return;
    }
    CGFloat enemyTarget;
    switch (enemyState) {
        case 0: case 2: enemyTarget = enemyPos.x - enemyReach; break;
        case 1: enemyTarget = enemyPos.x - 2.0 * enemyReach; break;
        case 3: enemyTarget = enemyPos.x; break;
        default: return;
    }
    enemyState = (enemyState + 1) % 4;
    CABasicAnimation *enemyAnim = [CABasicAnimation animationWithKeyPath:@"position"];
    enemyAnim.fromValue = [NSValue valueWithCGPoint:CGPointMake(enemySource, enemyPos.y)];
    enemyAnim.toValue = [NSValue valueWithCGPoint:CGPointMake(enemyTarget, enemyPos.y)];
    enemyAnim.duration = minEnemyDuration + arc4random_uniform(deltaEnemyDuration);
    enemyAnim.timingFunction = [CAMediaTimingFunction functionWithName:kCAMediaTimingFunctionLinear];
    enemyAnim.delegate = [AnimationDelegate onEnd:^{
        [self moveEnemyInRunLoop];
    }];
    [enemyLayer addAnimation:enemyAnim forKey:@"EnemyAnim"];
}

- (void)touchesEnded:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    if (gameOver && canRestart) {
        // Restart the game.
        gameOver = NO;
        canJump = YES;
        goLabel.text = @"";
        enemyState = 0;
        [self moveEnemyInRunLoop];
        return;
    }
    
    if (!canJump)
        return;
    
    [self jump];
}

@end
