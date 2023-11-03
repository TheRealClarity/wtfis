enum kstruct_offset {
    /* struct task */
    KSTRUCT_OFFSET_TASK_NEXT,
    KSTRUCT_OFFSET_TASK_PREV,
    KSTRUCT_OFFSET_TASK_ITK_SPACE,
    KSTRUCT_OFFSET_TASK_BSD_INFO,
    
    /* struct ipc_port */
    KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
    KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
    KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS,
    
    /* struct proc */
    KSTRUCT_OFFSET_PROC_PID,
    KSTRUCT_OFFSET_PROC_P_FD,
    KSTRUCT_OFFSET_PROC_P_UCRED,
    
    /* struct filedesc */
    KSTRUCT_OFFSET_FILEDESC_FD_OFILES,
    
    /* struct fileproc */
    KSTRUCT_OFFSET_FILEPROC_F_FGLOB,
    
    /* struct fileglob */
    KSTRUCT_OFFSET_FILEGLOB_FG_DATA,
    
    /* struct pipe */
    KSTRUCT_OFFSET_PIPE_BUFFER,
    
    /* struct ipc_space */
    KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE,
};

enum pfind_addr {
    PFIND_ADDR_INVALIDATE_TLB,
    PFIND_ADDR_FLUSHCACHE,
    PFIND_ADDR_ADD_X0_X0_0X40,
    PFIND_ADDR_CS_ENFORCEMENT_DISABLE,
    PFIND_ADDR_AMFI_GOOMW,
    PFIND_ADDR_MOUNT_COMMON,
    PFIND_ADDR_VM_FAULT_ENTER,
    //PFIND_ADDR_VM_MAP_ENTER,
    //PFIND_ADDR_VM_MAP_PROTECT,
    PFIND_ADDR_CRED_LABEL_UPDATE_EXECVE,
    PFIND_ADDR_TFP0,
    PFIND_ADDR_ICHDB_1,
    PFIND_ADDR_ICHDB_2,
    PFIND_ADDR_MAPIO,
    PFIND_ADDR_SB_TRACE,
    PFIND_ADDR_KERNEL_PMAP,
    PFIND_ADDR_PHYS_ADDR,
    PFIND_ADDR_ROOT_PATCH,
    PFIND_ADDR_SBOPS,
    PFIND_ADDR_KERNPROC,
    PFIND_ADDR_ROOTVNODE,
};

int koffset(enum kstruct_offset offset);
uint64_t patchfinderaddress(enum pfind_addr offset);

void offsets_init(void);
void set_pfaddr_arr(uint64_t* arr);
