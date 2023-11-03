//
//  jailbreak.h
//  wtfis
//
//  Created by TheRealClarity on 02/07/2023.
//  Copyright © 2023 Jake James. All rights reserved.
//

#ifndef jailbreak_h
#define jailbreak_h

#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <unistd.h>
#include <spawn.h>

#include <Foundation/Foundation.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>

#include "kernel_memory.h"
#include "patchfinder64.h"
#include "sbops.h"
#include "exploit_utilities.h"

#define Log(format, ...) { NSLog(format, ##__VA_ARGS__); }

extern int haxx(void);
int jailbreak(mach_port_t tfp0, uint64_t slide, uint64_t our_task_addr);
int dumpKernel(uint8_t* kernelDump, uint32_t size, uint64_t slide);

#endif /* jailbreak_h */
