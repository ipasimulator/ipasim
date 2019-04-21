//
//  ViewController.m
//  SampleApp
//
//  Created by Jan Jones on 3/19/19.
//  Copyright © 2019 Jan Jones. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()

@property (strong, nonatomic) UITextField *a, *b;
@property (strong, nonatomic) UILabel *plus, *eq, *c;

@end

@implementation ViewController

- (void)textFieldDidEndEditing:(UITextField *)textField {
    self.c.text = @(self.a.text.intValue + self.b.text.intValue).stringValue;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)viewWillLayoutSubviews {
    [super viewWillLayoutSubviews];
    
    CGRect bounds = [[UIScreen mainScreen] bounds];
    
    CGFloat height = 40.0f;
    CGRect aFrame = CGRectMake(0.0f, bounds.size.height / 2.0f - height, bounds.size.width / 5.0f, height);
    if (!self.a) {
        self.a = [[UITextField alloc] initWithFrame:aFrame];
        self.a.text = @"5";
        self.a.delegate = self;
        [self.view addSubview:self.a];
    } else
        self.a.frame = aFrame;
    
    CGRect plusFrame = CGRectMake(bounds.size.width / 5.0f, bounds.size.height / 2.0f - height, bounds.size.width / 5.0f, height);
    if (!self.plus) {
        self.plus = [[UILabel alloc] initWithFrame:plusFrame];
        self.plus.text = @"+";
        [self.view addSubview:self.plus];
    } else
        self.plus.frame = plusFrame;
        
    CGRect bFrame = CGRectMake(2.0f * bounds.size.width / 5.0f, bounds.size.height / 2.0f - height, bounds.size.width / 5.0f, height);
    if (!self.b) {
        self.b = [[UITextField alloc] initWithFrame:bFrame];
        self.b.text = @"10";
        self.b.delegate = self;
        [self.view addSubview:self.b];
    } else
        self.b.frame = bFrame;
    
    CGRect eqFrame = CGRectMake(3.0f * bounds.size.width / 5.0f, bounds.size.height / 2.0f - height, bounds.size.width / 5.0f, height);
    if (!self.eq) {
        self.eq = [[UILabel alloc] initWithFrame:eqFrame];
        self.eq.text = @"=";
        [self.view addSubview:self.eq];
    } else
        self.eq.frame = eqFrame;
    
    CGRect cFrame = CGRectMake(4.0f * bounds.size.width / 5.0f, bounds.size.height / 2.0f - height, bounds.size.width / 5.0f, height);
    if (!self.c) {
        self.c = [[UILabel alloc] initWithFrame:cFrame];
        self.c.text = @"15";
        [self.view addSubview:self.c];
    } else
        self.c.frame = cFrame;
}

@end
