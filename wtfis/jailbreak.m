//
//  jailbreak.c
//  wtfis
//
//  Created by TheRealClarity on 02/07/2023.
//  Copyright © 2023 TheRealClarity. All rights reserved.
//

#include "jailbreak.h"

#define KERNEL_BASE_ADDRESS (0xFFFFFF8002002000) /* iOS 8 */
#define KERN_DUMP_SIZE 0x1000000
#define NOP 0xD503201F
extern char **environ;

int dumpKernel(uint8_t* full_kern, uint32_t size, uint64_t slide)
{
    if ((size & 0xFFF) != 0)
        return -1;
    
    Log(@"[i] dumping kernel...");
    for (int i = 0; i < size; i+=4096)
    {
        uint8_t* data = (uint8_t*)malloc(4096);
        kread(KERNEL_BASE_ADDRESS + slide + i, data, 4096);
        memcpy(&full_kern[i], data, 4096);
    }
    Log(@"[i] kernel dump complete");
    return 0;
}

void print_addresses(uint64_t slide) {
    Log(@"[i]  INVALIDATE_TLB                             = 0x%.16llX", patchfinderaddress(PFIND_ADDR_INVALIDATE_TLB) - slide);
    Log(@"[i]  FLUSHCACHE                                 = 0x%.16llX", patchfinderaddress(PFIND_ADDR_FLUSHCACHE) - slide);
    Log(@"[i]  ADD_X0_X0_0X40                             = 0x%.16llX", patchfinderaddress(PFIND_ADDR_ADD_X0_X0_0X40) - slide);
    Log(@"[i]  CS_ENFORCEMENT_DISABLE                     = 0x%.16llX", patchfinderaddress(PFIND_ADDR_CS_ENFORCEMENT_DISABLE) - slide);
    Log(@"[i]  AMFI_GET_OUT_OF_MY_WAY                     = 0x%.16llX", patchfinderaddress(PFIND_ADDR_AMFI_GOOMW) - slide);
    Log(@"[i]  MOUNT_COMMON                               = 0x%.16llX", patchfinderaddress(PFIND_ADDR_MOUNT_COMMON) - slide);
    Log(@"[i]  VM_FAULT_ENTER                             = 0x%.16llX", patchfinderaddress(PFIND_ADDR_VM_FAULT_ENTER) - slide);
    //Log(@"[i]  VM_MAP_ENTER                               = 0x%.16llX", patchfinderaddress(PFIND_ADDR_VM_MAP_ENTER) - slide);
    //Log(@"[i]  VM_MAP_PROTECT                             = 0x%.16llX", patchfinderaddress(PFIND_ADDR_VM_MAP_PROTECT) - slide);
    Log(@"[i]  CRED_LABEL_UPDATE_EXECVE                   = 0x%.16llX", patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE) - slide);
    Log(@"[i]  TFP0                                       = 0x%.16llX", patchfinderaddress(PFIND_ADDR_TFP0) - slide);
    Log(@"[i]  ICHDB_1                                    = 0x%.16llX", patchfinderaddress(PFIND_ADDR_ICHDB_1) - slide);
    Log(@"[i]  ICHDB_2                                    = 0x%.16llX", patchfinderaddress(PFIND_ADDR_ICHDB_2) - slide);
    Log(@"[i]  MAPIO                                      = 0x%.16llX", patchfinderaddress(PFIND_ADDR_MAPIO) - slide);
    Log(@"[i]  SB_TRACE                                   = 0x%.16llX", patchfinderaddress(PFIND_ADDR_SB_TRACE) - slide);
    
    Log(@"[i]  KERNEL_PMAP                                = 0x%.16llX", patchfinderaddress(PFIND_ADDR_KERNEL_PMAP) - slide);
    Log(@"[i]  PHYS_ADDR                                  = 0x%.16llX", patchfinderaddress(PFIND_ADDR_PHYS_ADDR) - slide);
    Log(@"[i]  GET_R00T                                   = 0x%.16llX", patchfinderaddress(PFIND_ADDR_ROOT_PATCH) - slide);
    Log(@"[i]  SBOPS                                      = 0x%.16llX", patchfinderaddress(PFIND_ADDR_SBOPS) - slide);
}

#ifndef UNTETHER

NSString* getCurrentExecutablePath(void) {
    char path[256];
    uint32_t size = sizeof(path);
    _NSGetExecutablePath(path, &size);
    char* pt = realpath(path, 0);
    return [[NSString stringWithUTF8String:pt]  stringByDeletingLastPathComponent];
}

int copyFile(NSString* src, NSString* dest) {
    if (![[NSFileManager defaultManager] isReadableFileAtPath:src]) {
        Log(@"[!] %@ not found at specified path.", src);
        return -1;
    }
    [[NSFileManager defaultManager] createDirectoryAtPath: [dest  stringByDeletingLastPathComponent]
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:nil];
    return [[NSFileManager defaultManager] copyItemAtPath:src toPath:dest error:nil];
}

int check_bootstrap(void) {
    // bail if bootstap is already installed
    if (access("/.installed_wtfis", F_OK) == 0) {
        Log(@"[i] Looks like bootstrap is already installed.");
        return 0;
    } else {
        Log(@"[i] Patching the dyld_shared_cache...");
        int patch_dsc = haxx();
        if(patch_dsc == 0) {
            Log(@"[i] Successufly patched the dyld_shared_cache.");
            //for fucking good measure
            sync();
            sync();
            sync();
        } else if (patch_dsc == 1){
            Log(@"[i] Dyld_shared_cache is already patched.");
            //return 1;
        } else {
            Log(@"[!] Failed to patch dyld_shared_cache.");
            return -1;
        }
        
        //get current executable path
        NSString* execpath = getCurrentExecutablePath();
        NSString* tar = [execpath stringByAppendingPathComponent:@"tar"];
        NSString* tar_dest = @"/bin/tar";
        if (copyFile(tar, tar_dest) == 0) {
            Log(@"[!] %@ not found at specified path.", tar);
            return -1;
        }
        chmod("/bin/tar", 0777);
        
        pid_t pd = 0;
        int status = 0;
        if (access("/.installed_wtfis", F_OK) != 0) {
            Log(@"[i] Bootstrapping...");
            chdir("/");
            open("/.installed_wtfis", O_RDWR|O_CREAT);
            open("/.cydia_no_stash",O_RDWR|O_CREAT);
            const char* bootstrap = [[execpath stringByAppendingPathComponent:@"bootstrap.tar"] UTF8String];
            posix_spawn(&pd, "/bin/tar", 0, 0, (char**)&(const char*[]){"/bin/tar", "--preserve-permissions", "--no-overwrite-dir", "-xvf", bootstrap, NULL}, NULL);
            waitpid(pd, &status, 0);
            if (WIFEXITED(status)) {
                int es = WEXITSTATUS(status);
                if(es != 0) {
                    Log(@"[!] Bootstrap failed: %d\n", es);
                    return -1;
                }
            }
            Log(@"[i] Successufly bootstrapped.");
        }
        Log(@"[i] Untethering...");
        
        char* untether_loc = "/wtfis/untether";
        char* untether_victim = "/usr/libexec/CrashHousekeeping";
        if(rename(untether_victim ,"/usr/libexec/CrashHousekeeping_o") == 0) {
            Log(@"[i] Renamed CrashHousekeeping.");
        } else {
            Log(@"[!] Failed renaming CrashHousekeeping...");
            return -1;
        }
        
        Log(@"[i] Installing untether...");
        
        const char* untether_path = [[execpath stringByAppendingPathComponent:@"untether.tar"] UTF8String];
        posix_spawn(&pd, "/bin/tar", 0, 0, (char**)&(const char*[]){"/bin/tar", "--preserve-permissions", "--no-overwrite-dir", "-xvf", untether_path, NULL}, NULL);
        waitpid(pd, &status, 0);
        if (WIFEXITED(status)) {
            int es = WEXITSTATUS(status);
            if(es != 0) {
                Log(@"[!] Failed to install untether: %d\n", es);
                return -1;
            }
        }
        
        Log(@"[i] Creating symlinks...");
        
        if(symlink(untether_loc, untether_victim) == 0) {
            Log(@"[i] Successfully installed untether.");
        } else {
            Log(@"[!] Failed to symlink %s to %s...", untether_loc, untether_victim);
            return -1;
        }
        
        Log(@"[i] Flushing uicache...");
        
        posix_spawn(&pd, "/usr/bin/uicache", 0, 0, (char**)&(const char*[]){"/usr/bin/uicache", NULL}, environ);
        waitpid(pd, &status, 0);
        if (WIFEXITED(status)) {
            int es = WEXITSTATUS(status);
            if(es != 0) {
                Log(@"[!] uicache failed: %d\n", es);
                return -1;
            }
        }
        
        Log(@"[i] Moving LaunchDaemons...");
        
        NSString *oldLaunchDaemonsFolder = @"/System/Library/LaunchDaemons/";
        NSString *newLaunchDaemonsFolder = @"/Library/LaunchDaemons/";
        NSArray *blacklist = @[@"bootps.plist",
                               @"com.apple.CrashHousekeeping.plist",
                               @"com.apple.MobileFileIntegrity.plist",
                               @"com.apple.mDNSResponder.plist",
                               @"com.apple.mobile.softwareupdated.plist",
                               @"com.apple.softwareupdateservicesd.plist"];
        
        NSString *file;
        NSError *error;
        NSDirectoryEnumerator *filesEnumerator = [[NSFileManager defaultManager] enumeratorAtPath:oldLaunchDaemonsFolder];
        NSFileManager *fm = [NSFileManager defaultManager];
        
        while (file = [filesEnumerator nextObject]) {
            NSRange range = [file rangeOfString:@"com.apple.jetsamproperties.*.plist" options:NSRegularExpressionSearch];
            if (![blacklist containsObject:file]) {
                if (range.location == NSNotFound) {
                    Log(@"[i] Moving %s", [file UTF8String]);
                    [fm moveItemAtPath:[oldLaunchDaemonsFolder stringByAppendingPathComponent:file]
                                toPath:[newLaunchDaemonsFolder stringByAppendingPathComponent:file]
                                 error:&error];
                    if(error) {
                        Log(@"[!] Failed to move %s to %s.", [file UTF8String], [newLaunchDaemonsFolder UTF8String]);
                    }
                    continue;
                }
            }
            Log(@"[i] Ignoring file %s", [file UTF8String]);
        }
        
        Log(@"[i] Moving NanoLaunchDaemons...");
        
        mkdir("/Library/NanoLaunchDaemons", 0755);
        NSString *oldNanoLaunchDaemonsFolder = @"/System/Library/NanoLaunchDaemons/";
        NSString *newNanoLaunchDaemonsFolder = @"/Library/NanoLaunchDaemons/";
        filesEnumerator = [[NSFileManager defaultManager] enumeratorAtPath:oldNanoLaunchDaemonsFolder];
        while (file = [filesEnumerator nextObject]) {
            Log(@"[i] Moving nld %s", [file UTF8String]);
            [fm moveItemAtPath:[oldNanoLaunchDaemonsFolder stringByAppendingPathComponent:file]
                        toPath:[newNanoLaunchDaemonsFolder stringByAppendingPathComponent:file]
                         error:&error];
            if(error) {
                Log(@"[!] Failed to move nld %s to %s.", [file UTF8String], [newNanoLaunchDaemonsFolder UTF8String]);
            }
        }
        
        rename("/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist", "/System/Library/LaunchDaemons/com.apple.mobile.softwareupdated.plist_");
        rename("/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist", "/System/Library/LaunchDaemons/com.apple.softwareupdateservicesd.plist_");
        rename("/System/Library/LaunchDaemons/com.apple.mDNSResponder.plist", "/System/Library/LaunchDaemons/com.apple.mDNSResponder.plist_");
        
        //install untether deb
        NSString* untether_deb = [execpath stringByAppendingPathComponent:@"com.trc.wtfisuntether_iphoneos-arm.deb"];
        NSString* untether_deb_dst_path = @"/var/root/Media/Cydia/AutoInstall/com.trc.wtfisuntether_iphoneos-arm.deb";
        if (copyFile(untether_deb, untether_deb_dst_path) == 0) {
            Log(@"[!] %@ not found at specified path.", untether_deb);
            return -1;
        }
        
        //install our source
        NSString* cydia_source = [execpath stringByAppendingPathComponent:@"wtfis.list"];
        NSString* cydia_source_dest = @"/etc/apt/sources.list.d/wtfis.list";
        if (copyFile(cydia_source, cydia_source_dest) == 0) {
            Log(@"[!] %@ not found at specified path.", untether_deb);
            return -1;
        }
        
        Log(@"[i] Done installing bootstrap.");
        Log(@"[i] Rebooting...");
        reboot(0);
    }
    return 0;
}
#endif

int jailbreak(mach_port_t tfp0, uint64_t slide, uint64_t our_task_addr) {
    Log(@"Slide 0x%.8llX", slide);
    uint8_t* full_kern = (uint8_t*)malloc(KERN_DUMP_SIZE);
    dumpKernel(full_kern, KERN_DUMP_SIZE , slide);
    
    uint64_t pf_array[19] = {0};
    int cnt = 0;
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_invalidate_tlb(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_flushcache(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_add_x0_x0_0x40(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_cs_enforcement_disable(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    pf_array[cnt]   = pf_array[cnt - 1] - 1; cnt++;
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_mount_common(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_vm_fault_enter(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    //pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_vm_map_enter(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    //pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_vm_map_protect(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_cred_label_update_execve(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_tfp0(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_ICHDB_1(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_ICHDB_2(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_mapIO(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);//0xFFFFFF8002F2AEEC;
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_sbtrace(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);//0xFFFFFF8002C2A75C;
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_pmap_location(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_phys_addr(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_get_root(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_sandbox_mac_policy_ops(KERNEL_BASE_ADDRESS + slide, full_kern, KERN_DUMP_SIZE);
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_kernproc(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    pf_array[cnt++] = KERNEL_BASE_ADDRESS + slide + find_rootvnode(KERNEL_BASE_ADDRESS, full_kern, KERN_DUMP_SIZE);
    
    set_pfaddr_arr(pf_array);
    print_addresses(slide);
    init_kcall(our_task_addr);
    
    
    uint64_t pages[50];
    
    int page_cnt = 0;
    pages[page_cnt++] = patchfinderaddress(PFIND_ADDR_VM_FAULT_ENTER)                        & (~0xFFF); // 0
    //pages[page_cnt++] = patchfinderaddress(PFIND_ADDR_VM_MAP_ENTER)                          & (~0xFFF); // 1
    //pages[page_cnt++] = patchfinderaddress(PFIND_ADDR_VM_MAP_PROTECT)                        & (~0xFFF); // 2
    //pages[page_cnt++] = patchfinderaddress(PFIND_ADDR_MOUNT_COMMON)                          & (~0xFFF); // 3
    pages[page_cnt++] = patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE)            & (~0xFFF); // 4
    //pages[page_cnt++] = patchfinderaddress(PFIND_ADDR_TFP0)                                  & (~0xFFF); // 5
    pages[page_cnt++] = patchfinderaddress(PFIND_ADDR_ICHDB_1)                               & (~0xFFF); // 6
    pages[page_cnt++] = patchfinderaddress(PFIND_ADDR_ICHDB_2)                               & (~0xFFF); // 7
    pages[page_cnt++] = patchfinderaddress(PFIND_ADDR_MAPIO)                                 & (~0xFFF); // 8
    //pages[page_cnt++] = patchfinderaddress(PFIND_ADDR_SB_TRACE)                              & (~0xFFF); // 9
    //pages[page_cnt++] = patchfinderaddress(PFIND_ADDR_ROOT_PATCH)                            & (~0xFFF); // 10
    
    // work with memory pages
    // get PDE
    uint64_t pmap_store = rk64(patchfinderaddress(PFIND_ADDR_KERNEL_PMAP));
    Log(@"[i] pmap_store: 0x%.16llX", pmap_store);
    uint64_t pde_base = rk64(pmap_store);
    Log(@"[i] pde_base:   0x%.16llX", pde_base);
    
    // get Physical and Virtual bases
    uint64_t gPhysBase = rk64(patchfinderaddress(PFIND_ADDR_PHYS_ADDR));
    Log(@"[i] pde_base: gPhysBase:  0x%.16llX", gPhysBase);
    uint64_t gVirtBase = rk64(patchfinderaddress(PFIND_ADDR_PHYS_ADDR) - 8);
    Log(@"[i] gVirtBase:  0x%.16llX", gVirtBase);
    
    // thanks @PanguTeam
    const uint64_t addr_start = 0xffffff8000000000; // Analytical kernel page table starting address (25 bits to 1, TTBR1_EL1 setting)
    // Up to 3 levels mapping. For 4KB page granule Level1 describes mapping of 1Gb, Level2 - 2Mb
    // First, read the value of stage1
    uint64_t level1_data = rk64(pde_base);
    
    // read level2 (each corresponds to 2Mb)
    uint64_t level2_base = (level1_data & 0xfffffff000) - gPhysBase + gVirtBase;
    uint64_t level2_krnl = level2_base + (((KERNEL_BASE_ADDRESS + slide - addr_start) >> 21) << 3);
    
    // placeholder for 30Mb (15 Level2 entries)
    uint64_t level2_data[15] = {0};
    Log(@"[i] level2_base 0x%.16llX level2_krnl 0x%.16llX", level2_base, level2_krnl);
    
    // read 16 Level2 entries (30Mb)
    for (int i = 0; i < 15; i++) {
        level2_data[i] = rk64(level2_krnl+(i*8));
        Log(@"[i] level2_data[%2d] = 0x%.16llX", i, level2_data[i]);
    }
    
    static const uint64_t kPageDescriptorType_Mask          = 0b11;
    static const uint64_t kPageDescriptorType_Block         = 0b01;
    static const uint64_t kPageDescriptorType_Table         = 0b11;
    
    static const uint64_t kPageDescriptorAP_Mask            = 0b11000000;
    static const uint64_t kPageDescriptorAP_Shift           = 6;
    static const uint64_t kPageDescriptorAP_EL1_RW_EL0_N    = 0b00;
    
    struct PagePatches {
        uint64_t address;
        uint64_t data;
    } pages_patches[50] = {0};
    uint32_t pages_patch_cnt = 0;
    
    // Rewritten page table
    for (int i = 0; i < page_cnt; i++)
    {
        uint64_t rw_page_base = pages[i];
        
        // First check level2 corresponds to the table
        int idx = (int)(((rw_page_base - addr_start) >> 21) - (((KERNEL_BASE_ADDRESS + slide) - addr_start) >> 21));
        
        uint64_t level2_entry = level2_data[idx];
        
        // Handle L2 'block' descriptors
        if ((level2_entry & kPageDescriptorType_Mask) != kPageDescriptorType_Table)
        {
            if ((level2_entry & kPageDescriptorType_Mask) != kPageDescriptorType_Block) {
                Log(@"[i] pages[%2d:%.16llX] -> L1[%2d:%.16llX] invalid L2 entry found", i, rw_page_base, idx, level2_entry);
                continue;
            }
            
            // Patch L2 descriptors
            if (((level2_entry & kPageDescriptorAP_Mask) >> kPageDescriptorAP_Shift) != kPageDescriptorAP_EL1_RW_EL0_N)
            {
                uint64_t level2_addr = level2_krnl+(idx*8);
                bool found = false;
                for (uint32_t i=0; i < pages_patch_cnt; i++)
                {
                    if (pages_patches[i].address == level2_addr)
                        found = true;
                    continue;
                }
                
                if(found)
                    continue;
                
                pages_patches[pages_patch_cnt].address = level2_addr;
                pages_patches[pages_patch_cnt].data = level2_entry;
                
                // clean AP bits
                level2_entry &= ~kPageDescriptorAP_Mask;
                
                // set AP: EL1 to RW, EL0 to None (value is actaully 0b00, code is just for readability)
                // level2_entry |= (kPageDescriptorAP_EL1_RW_EL0_N << kPageDescriptorAP_Shift) & kPageDescriptorAP_Mask
                
                // 32bit write is enough to covering lower attributes
                wk32(level2_addr, (uint32_t)level2_entry);
                
                Log(@"[i] pages[%2d:%.16llX] -> L2[0x%.16llX] patch %.16llX -> %.16llX", i, rw_page_base, level2_addr, pages_patches[pages_patch_cnt].data, level2_entry);
                pages_patch_cnt++;
                
                continue;
            }
            else
            {
                Log(@"[i] pages[%2d:%.16llX] -> L3[0x%.16llX] skip %.16llX", i, rw_page_base, level2_krnl+(idx*8), level2_entry);
            }
        }
        // Handle L2 'table' descriptors
        
        // Level3, each corresponding to a 4K page
        uint64_t level3_base = (level2_entry & 0xfffffff000) - gPhysBase + gVirtBase;
        uint64_t level3_krnl = level3_base + (((rw_page_base & 0x1fffff) >> 12) << 3);
        
        Log(@"[i] pages[%2d:%.16llX] -> L2[%d] = L2: 0x%.16llX, level3_base: 0x%.16llX, pte_krnl: 0x%.16llX", i, rw_page_base, idx, level2_entry, level3_base, level3_krnl);
        
        // read pte
        uint64_t level3_entry = rk64(level3_krnl);
        
        // Patch L3 descriptors
        if (((level3_entry & kPageDescriptorAP_Mask) >> kPageDescriptorAP_Shift) != kPageDescriptorAP_EL1_RW_EL0_N)
        {
            bool found = false;
            for (uint32_t i=0; i < pages_patch_cnt; i++)
            {
                if (pages_patches[i].address == level3_krnl)
                    found = true;
                continue;
            }
            
            if(found)
                continue;
            
            pages_patches[pages_patch_cnt].address = level3_krnl;
            pages_patches[pages_patch_cnt].data = level3_entry;
            
            // clean AP bits
            level3_entry &= ~kPageDescriptorAP_Mask;
            
            // set AP: EL1 to RW, EL0 to None (value is actaully 0b00, code is just for readability)
            // level3_data |= (kPageDescriptorAP_EL1_RW_EL0_N << kPageDescriptorAP_Shift) & kPageDescriptorAP_Mask
            
            // 32bit write is enough to covering lower attributes
            wk32(level3_krnl, (uint32_t)level3_entry);
            Log(@"[i] pages[%2d:%.16llX] -> L3[0x%.16llX] patch %.16llX -> %.16llX", i, rw_page_base, level3_krnl, pages_patches[pages_patch_cnt].data, level3_entry);
            pages_patch_cnt++;
        }
        else
        {
            Log(@"[i] pages[%2d:%.16llX] -> L3[0x%.16llX] skip %.16llX", i, rw_page_base, level3_krnl, level3_entry);
        }
    }
    
    // Invalidate TLB and flush cache
    kcall(patchfinderaddress(PFIND_ADDR_INVALIDATE_TLB), 1, 0, 0, 0, 0, 0, 0);
    kcall(patchfinderaddress(PFIND_ADDR_FLUSHCACHE), 1, 0, 0, 0, 0, 0, 0);
    
    /* patch le sandbox */
    Log(@"[i] Patching SBOPS...");
    
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_file_check_mmap),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_rename),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_rename),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_access),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_chroot),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_create),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_exec),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_link),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_open),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_readlink),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_setflags),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_setmode),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_setowner),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_stat),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_truncate),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_unlink),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_notify_create),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_vnode_check_getattr),0);
    wk64(patchfinderaddress(PFIND_ADDR_SBOPS)+offsetof(struct mac_policy_ops, mpo_mount_check_stat),0);
    
    
    
    //Log(@"[i] Patching kernel...");
    //Log(@"[i] Patching TFP0...");
    //wk32(patchfinderaddress(PFIND_ADDR_TFP0), 0xD503201F);
    kcall(patchfinderaddress(PFIND_ADDR_FLUSHCACHE), 1, 0, 0, 0, 0, 0, 0);
    
    Log(@"[i] Patching VM FAULT...");
    wk32(patchfinderaddress(PFIND_ADDR_VM_FAULT_ENTER), 0x5280002d); // mov x13, #0x1
    //    Log(@"[i] Patching VM MAP...");
    //    wk32(patchfinderaddress(PFIND_ADDR_VM_MAP_ENTER), 0x2a0803ea); // mov x10, x8
    //    Log(@"[i] Patching VM PROTECT...");
    //    wk32(patchfinderaddress(PFIND_ADDR_VM_MAP_PROTECT), NOP);
    
    //wk32(patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE_1), NOP);
    
    wk32(patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE), NOP);                   // NOP
    wk32(patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE) + 0x4, 0xB9400268);      // LDR W8, [X19]
    wk32(patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE) + 0x8, 0x32000D08);      // ORR W8, W8, #0xF
    wk32(patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE) + 0xC, 0x32060108);      // ORR W8, W8, #0x4000000
    wk32(patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE) + 0x10, 0x12136908);     // BIC W8, W8, #0xFF00
    wk32(patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE) + 0x14, 0xB9000268);     // STR W8, [X19]
    wk32(patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE) + 0x18, 0xD2800000);     // MOV X0, #0
    wk32(patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE) + 0x1C, 0xD10083BF);     // SUB SP, x29, #0x20
    wk32(patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE) + 0x20, 0xA9427BFD);     // LDP x29, x30, [SP, #0x20]
    wk32(patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE) + 0x24, 0xA9414FF4);     // LDP x20, x19, [SP, #0x10]
    wk32(patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE) + 0x28, 0xA8C357F6);     // LDP x22, x21, [SP], #0x30
    wk32(patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE) + 0x2C, 0xD65F03C0);     // RET
    wk32(patchfinderaddress(PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE) + 0x30, NOP);            // NOP
    
    Log(@"[i] Patching ICANHASDEBUGGER1...");
    wk32(patchfinderaddress(PFIND_ADDR_ICHDB_1), NOP);
    Log(@"[i] Patching ICANHASDEBUGGER2...");
    wk32(patchfinderaddress(PFIND_ADDR_ICHDB_2), 0x52800020); // mov x0, #0x1
    //Log(@"[i] Patching SBTRACE...");
    //wk32(patchfinderaddress(PFIND_ADDR_SB_TRACE), NOP);
    Log(@"[i] Patching MAPIO...");
    wk32(patchfinderaddress(PFIND_ADDR_MAPIO), NOP);
    Log(@"[i] Patching CSENFORCEMENT DISABLE...");
    wk32(patchfinderaddress(PFIND_ADDR_CS_ENFORCEMENT_DISABLE), 1);
    Log(@"[i] Patching AMFI_GOOMW...");
    wk32(patchfinderaddress(PFIND_ADDR_AMFI_GOOMW), 1);
    
    kcall(patchfinderaddress(PFIND_ADDR_FLUSHCACHE), 1, 0, 0, 0, 0, 0, 0);
    
    uint64_t kernproc = patchfinderaddress(PFIND_ADDR_KERNPROC);
    uint64_t proc = rk64(kernproc);
    uint32_t our_pid = getpid();
    uint64_t our_proc = 0;
    uint64_t kern_proc = 0;
    while (proc) {
        uint32_t pid = (uint32_t)rk64(proc + koffset(KSTRUCT_OFFSET_PROC_PID));
        if (pid == our_pid) {
            our_proc = proc;
        } else if (pid == 0) {
            kern_proc = proc;
        }
        proc = rk64(proc + 0x8);
    }
    //uint64_t ourcred = rk64(our_proc + koffset(KSTRUCT_OFFSET_PROC_P_UCRED));
    uint64_t kern_cred = rk64(kern_proc + koffset(KSTRUCT_OFFSET_PROC_P_UCRED));
    wk64(our_proc + koffset(KSTRUCT_OFFSET_PROC_P_UCRED), kern_cred);
    setuid(0);
    uid_t myuid = getuid();
    Log(@"[i] Who am I: %d", myuid);
    if(myuid != 0) {
        return -1;
    }
    vm_offset_t off = 0xd8;
    
    uint64_t _rootvnode = patchfinderaddress(PFIND_ADDR_ROOTVNODE);
    uint64_t rootfs_vnode = rk64(_rootvnode);
    uint64_t v_mount = rk64(rootfs_vnode + off);
    uint32_t v_flag = rk32(v_mount + 0x79);
    
    wk32(v_mount + 0x79, v_flag & ~(1 << 6));
    
    char* nm = strdup("/dev/disk0s1s1");
    int mntr = mount("hfs", "/", MNT_UPDATE, &nm);
    Log(@"[i] Remounting / as read/write %d (%s)", mntr, (mntr != 0)? strerror(errno) : "done");
    if(mntr != 0) {
        return -1;
    }
    
    v_mount = rk64(rootfs_vnode + off);
    wk32(v_mount + 0x79, v_flag);
    
    Log(@"[i] revert patched page descriptors (%d)", pages_patch_cnt);
    for (uint32_t i=0; i < pages_patch_cnt ; i--)
    {
        // 32bit write is enough to covering lower attributes
        wk32(pages_patches[i].address, (uint32_t)pages_patches[i].data);
        Log(@"[i] L3[0x%.16llX] revert to %.16llX", pages_patches[i].address, pages_patches[i].data);
    }
    
    kcall(patchfinderaddress(PFIND_ADDR_INVALIDATE_TLB), 1, 0, 0, 0, 0, 0, 0);
    kcall(patchfinderaddress(PFIND_ADDR_FLUSHCACHE), 1, 0, 0, 0, 0, 0, 0);
    
    Log(@"[i] ... done");
    
    //test fork
    
    int f = fork();
    if (f == 0) {
        exit(0);
    }
    waitpid(f, 0, 0);
    
    if(f < 0) {
        return -1;
    }
#ifndef UNTETHER
    int cb = check_bootstrap();
    if(cb < 0) {
        return -1;
    }
#endif
    pid_t pid = 0;
    posix_spawn(&pid, "/bin/bash", NULL, NULL, (char **)&(const char*[]){ "/bin/bash", "/wtfis/loadruncmd", NULL }, environ);
    waitpid(pid, 0, 0);
    posix_spawn(&pid, "/bin/launchctl", NULL, NULL, (char **)&(const char*[]){ "/bin/launchctl", "load", "/Library/LaunchDaemons", NULL }, environ);
    waitpid(pid, 0, 0);
    posix_spawn(&pid, "/bin/launchctl", NULL, NULL, (char **)&(const char*[]){ "/bin/launchctl", "load", "/Library/NanoLaunchDaemons", NULL }, environ);
    waitpid(pid, 0, 0);
#ifndef UNTETHER
    //goodbye
    posix_spawn(&pid, "/usr/bin/killall", NULL, NULL, (char **)&(const char*[]){ "/usr/bin/killall", "-9", "backboardd", NULL }, environ);
    Log(@"Reloading SpringBoard...");
#endif
    return 0;
}
