#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>

#import "offsets.h"

#define SYSTEM_VERSION_EQUAL_TO(v)                  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedSame)
#define SYSTEM_VERSION_GREATER_THAN(v)              ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedDescending)
#define SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(v)  ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN(v)                 ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] == NSOrderedAscending)
#define SYSTEM_VERSION_LESS_THAN_OR_EQUAL_TO(v)     ([[[UIDevice currentDevice] systemVersion] compare:v options:NSNumericSearch] != NSOrderedDescending)

int* offsets = NULL;
uint64_t* pfaddr_arr = NULL;

int kstruct_offsets_8_4[] = {
    0x30,  // KSTRUCT_OFFSET_TASK_NEXT,
    0x38,  // KSTRUCT_OFFSET_TASK_PREV,
    0x288, // KSTRUCT_OFFSET_TASK_ITK_SPACE
    0x2f0, // KSTRUCT_OFFSET_TASK_BSD_INFO
    
    0x60,  // KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER
    0x68,  // KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT
    0x94,  // KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS // maybe...?
    
    0x10,  // KSTRUCT_OFFSET_PROC_PID
    0xF0,  // KSTRUCT_OFFSET_PROC_P_FD
    0xE8,  // KSTRUCT_OFFSET_PROC_P_UCRED
    
    0x0,   // KSTRUCT_OFFSET_FILEDESC_FD_OFILES
    
    0x8,   // KSTRUCT_OFFSET_FILEPROC_F_FGLOB
    
    0x38,  // KSTRUCT_OFFSET_FILEGLOB_FG_DATA
    
    0x10,  // KSTRUCT_OFFSET_PIPE_BUFFER
    
    0x20,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE
};

int kstruct_offsets_9_3[] = {
    0x30,  // KSTRUCT_OFFSET_TASK_NEXT,
    0x38,  // KSTRUCT_OFFSET_TASK_PREV,
    0x2a0, // KSTRUCT_OFFSET_TASK_ITK_SPACE,
    0x308, // KSTRUCT_OFFSET_TASK_BSD_INFO,
    
    0x58,  // KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
    0x60,  // KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
    0x94,  // KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS
    
    0x10,  // KSTRUCT_OFFSET_PROC_PID,
    0x120, // KSTRUCT_OFFSET_PROC_P_FD
    0xE8,  // KSTRUCT_OFFSET_PROC_P_UCRED fix for iOS 9
    
    0x0,   // KSTRUCT_OFFSET_FILEDESC_FD_OFILES
    
    0x8,   // KSTRUCT_OFFSET_FILEPROC_F_FGLOB
    
    0x38,  // KSTRUCT_OFFSET_FILEGLOB_FG_DATA
    
    0x10,  // KSTRUCT_OFFSET_PIPE_BUFFER
    
    0x20,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE
};

/*
 int kstruct_offsets_10_x[] = {
 0xb,   // KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE,
 0x10,  // KSTRUCT_OFFSET_TASK_REF_COUNT,
 0x14,  // KSTRUCT_OFFSET_TASK_ACTIVE,
 0x20,  // KSTRUCT_OFFSET_TASK_VM_MAP,
 0x28,  // KSTRUCT_OFFSET_TASK_NEXT,
 0x30,  // KSTRUCT_OFFSET_TASK_PREV,
 0xd8,  // KSTRUCT_OFFSET_TASK_ITK_SELF,
 0x300, // KSTRUCT_OFFSET_TASK_ITK_SPACE,
 0x360, // KSTRUCT_OFFSET_TASK_BSD_INFO,
 
 0x0,   // KSTRUCT_OFFSET_IPC_PORT_IO_BITS,
 0x4,   // KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES,
 0x40,  // KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE,
 0x50,  // KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT,
 0x60,  // KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
 0x68,  // KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
 0x88,  // KSTRUCT_OFFSET_IPC_PORT_IP_PREMSG,
 0x90,  // KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT,
 0xa0,  // KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS,
 
 0x10,  // KSTRUCT_OFFSET_PROC_PID,
 0x108, // KSTRUCT_OFFSET_PROC_P_FD
 
 0x0,   // KSTRUCT_OFFSET_FILEDESC_FD_OFILES
 
 0x8,   // KSTRUCT_OFFSET_FILEPROC_F_FGLOB
 
 0x38,  // KSTRUCT_OFFSET_FILEGLOB_FG_DATA
 
 0x10,  // KSTRUCT_OFFSET_SOCKET_SO_PCB
 
 0x10,  // KSTRUCT_OFFSET_PIPE_BUFFER
 
 0x14,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE_SIZE
 0x20,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE
 
 0x6c,  // KFREE_ADDR_OFFSET
 };
 */

int koffset(enum kstruct_offset offset) {
    if (offsets == NULL) {
        printf("need to call offsets_init() prior to querying offsets\n");
        return 0;
    }
    return offsets[offset];
}

void set_pfaddr_arr(uint64_t* arr) {
    pfaddr_arr = arr;
}

uint64_t patchfinderaddress(enum pfind_addr offset) {
    if (pfaddr_arr == NULL) {
        printf("Patchfinder didn't run yet!\n");
        return 0;
    }
    return pfaddr_arr[offset];
}


void offsets_init(void) {
    if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"9.3")) {
        printf("[i] offsets selected for iOS 9.3.x\n");
        offsets = kstruct_offsets_9_3;
        //    } else if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"8.0")) {
        //        printf("[i] offsets selected for iOS 10.x\n");
        //        offsets = kstruct_offsets_10_x;
    } else if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"8.0")) {
        printf("[i] offsets selected for iOS 8.4.x\n");
        offsets = kstruct_offsets_8_4;
        //    } else if (SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"8.0")) {
        //        printf("[i] offsets selected for iOS 10.x\n");
        //        offsets = kstruct_offsets_10_x;
    } else {
        printf("[-] iOS version too low, 8.4 required\n");
        exit(EXIT_FAILURE);
    }
}
