//
//  ViewController.m
//  wtfis
//
//  Created by TheRealClarity on 02/07/2023.
//  Copyright © 2023 TheRealClarity. All rights reserved.
//

#import "ViewController.h"
#include "exploit.h"
#include "jailbreak.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    NSArray* dirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var" error:Nil];
    if(dirs){
        NSLog(@"[!] Already jailbroken, bailing.");
        exit(0);
    }
    [super viewDidLoad];
}

- (IBAction)go:(UIButton*)sender {
    [sender setEnabled:NO];
    [sender setTitle:@"Exploiting..." forState:UIControlStateDisabled];
    NSLog(@"[i] Give me tfp0");
    mach_port_t tfp0 = get_tfp0();
    if(tfp0 == 0) {
        NSLog(@"[!] Failed to get tfp0!");
        [sender setTitle:@"wtf?" forState:UIControlStateDisabled];
        [sender setNeedsLayout];
        [sender layoutIfNeeded];
        return;
    }
    NSLog(@"[i] Give me kslide");
    uint64_t slide = get_kernel_slide();
    int lol = jailbreak(tfp0, slide, our_task_addr);
    if(lol){
        UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"LOG" message:@"Fail" delegate:self cancelButtonTitle:@"OK" otherButtonTitles:@"OK", nil];
        [alert show];
    }
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
