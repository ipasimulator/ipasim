//
//  ViewController.m
//  IpasimBenchmark
//
//  Created by Jan Jones on 4/21/19.
//  Copyright © 2019 Jan Jones. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()

@property (strong, nonatomic) UILabel *status;
@property (strong, nonatomic) UIButton *start;

@end

// Benchmarking function from `libdispatch`
extern uint64_t dispatch_benchmark(size_t count, void (^block)(void));

@implementation ViewController

- (void)log:(NSString *)message {
    self.status.text = [self.status.text stringByAppendingString:@"\n"];
    self.status.text = [self.status.text stringByAppendingString:message];
}

- (void)benchmark:(NSString *)title count:(size_t)count block:(void(^)(void))block {
    uint64_t time = dispatch_benchmark(count, block);
    [self log:[title stringByAppendingString:[@": " stringByAppendingString:@(time).stringValue]]];
}

- (id)noop {
    return self;
}

- (void)onStart {
    [self log:@"Started."];

    [self benchmark:@"-[NSObject hash]" count:10000 block:^{
        [self hash];
    }];

    [self benchmark:@"-[ViewController noop]" count:10000 block:^{
        [self noop];
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
