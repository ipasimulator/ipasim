//
//  ViewController.m
//  IpasimBenchmark
//
//  Created by Jan Jones on 4/21/19.
//  Copyright © 2019 Jan Jones. All rights reserved.
//

#import "ViewController.h"

#import <objc/runtime.h>

@interface ViewController ()

@property (strong, nonatomic) UILabel *status;
@property (strong, nonatomic) UIButton *start;

- (id)noop;

@end

// Benchmarking functions from `libdispatch`
extern uint64_t dispatch_benchmark(size_t count, void (^block)(void));
extern uint64_t dispatch_benchmark_f(size_t count, void *ctxt, void (*func)(void *));

static void funcNoop(void *self) { [(__bridge ViewController *)self noop]; }
static void staticNoop(void *ctx) {}

@implementation ViewController

- (void)log:(NSString *)message {
    self.status.text = [self.status.text stringByAppendingString:@"\n"];
    self.status.text = [self.status.text stringByAppendingString:message];
}

- (void)log:(NSString *)title time:(uint64_t)time {
    [self log:[title stringByAppendingString:[@": " stringByAppendingString:@(time).stringValue]]];
}

- (void)benchmark:(NSString *)title count:(size_t)count block:(void(^)(void))block {
    uint64_t time = dispatch_benchmark(count, block);
    [self log:title time:time];
}

- (void)benchmark:(NSString *)title count:(size_t)count ctx:(void *)ctx func:(void(*)(void *))func {
    uint64_t time = dispatch_benchmark_f(count, ctx, func);
    [self log:title time:time];
}

- (id)noop {
    return self;
}

- (size_t)noSyscalls {
    size_t result = 1;
    for (size_t i = 120; i != 0; --i)
        result *= i;
    return result;
}

- (void)onStart {
    [self log:@"Started."];

    const size_t count = 20000;
    
    [self benchmark:@"-[NSObject hash]" count:count block:^{
        [self hash];
    }];

    [self benchmark:@"-[ViewController noop] (block)" count:count block:^{
        [self noop];
    }];

    [self benchmark:@"-[ViewController noop] (func)" count:count ctx:(__bridge void *)(self) func:funcNoop];

    [self benchmark:@"staticNoop" count:count ctx:NULL func:staticNoop];
    
    [self benchmark:@"objc_getClass (block)" count:count block:^{
        objc_getClass("ViewController");
    }];
    
    [self benchmark:@"objc_getClass (func)" count:count ctx:"ViewController" func:(void(*)(void *))objc_getClass];
    
    [self benchmark:@"object_isClass" count:count ctx:NULL func:(void(*)(void *))object_isClass];

    [self benchmark:@"-[ViewController viewWillLayoutSubviews]" count:count block:^{
        [self viewWillLayoutSubviews];
    }];

    [self benchmark:@"-[ViewController noSyscalls]" count:count block:^{
        [self noSyscalls];
    }];
}

- (void)viewDidLoad {
    [super viewDidLoad];

    CGRect bounds = self.view.bounds;

    self.status = [[UILabel alloc] initWithFrame:bounds];
    self.status.text = @"Ready.";
    self.status.textAlignment = NSTextAlignmentCenter;
    self.status.lineBreakMode = NSLineBreakByWordWrapping;
    self.status.numberOfLines = 0; // allow unlimited number of lines
    [self.view addSubview:self.status];

    self.start = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.start setTitle:@"Start" forState:UIControlStateNormal];
    [self.start addTarget:self action:@selector(onStart) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.start];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)viewWillLayoutSubviews {
    [super viewWillLayoutSubviews];

    CGRect bounds = self.view.bounds;
    CGFloat padding = 30.0f;
    CGFloat height = 50.0f;
    self.status.frame = CGRectMake(0.0f, height, bounds.size.width, bounds.size.height - height);
    self.start.frame = CGRectMake(0.0f, padding, bounds.size.width, height - padding);
}

@end
