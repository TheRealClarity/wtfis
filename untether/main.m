//
//  main.c
//  codename_wtfis
//
//  Created by TheRealClarity on 06/08/2023.
//  Copyright © 2023 TheRealClarity. All rights reserved.
//

#include "exploit.h"
#include "jailbreak.h"
#include <Foundation/NSObjCRuntime.h>
#include <stdio.h>

#ifdef UNTETHER
int main(void) {
#ifdef DEBUG_UNTETHER
  int fd = open("/var/mobile/Media/.loli", O_RDWR | O_CREAT);
  dup2(fd, 1);
#else
  if (access("/var/mobile/Media/.loli", F_OK) == 0) {
    remove("/var/mobile/Media/.loli");
  }
#endif
  NSLog(@"[i] Give me tfp0");
  mach_port_t tfp0 = get_tfp0();
  if (tfp0 == 0) {
    NSLog(@"[!] Failed to get tfp0!");
    return -69;
  }
  NSLog(@"[i] Give me kslide");
  uint64_t slide = get_kernel_slide();
  int lol = jailbreak(tfp0, slide, our_task_addr);
  if (lol == 0) {
    NSLog(@"[i] Jailbreak successful");
    return 0;
  }
  NSLog(@"[!] Failed to patch Kernel!");
  return -1;
}
#endif
