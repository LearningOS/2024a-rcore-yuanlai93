
//! Process management syscalls
use crate::{
    config::{
        MAX_SYSCALL_NUM,
        PAGE_SIZE
    },
    task::{
        change_program_brk, 
        exit_current_and_run_next, 
        suspend_current_and_run_next, 
        TaskStatus,
        current_user_token,
        get_syscall_times,
        get_time_first_called,
        get_app_memory_set,
    },
    timer::{
        get_time_us,
        get_time_ms,
    },
    mm::{
        translated_byte_buffer,
        MapPermission,
        VirtAddr,
    },
};
#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Task information
#[allow(dead_code)]
pub struct TaskInfo {
    /// Task status in it's life cycle
    status: TaskStatus,
    /// The numbers of syscall called by task
    syscall_times: [u32; MAX_SYSCALL_NUM],
    /// Total running time of task
    time: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// YOUR JOB: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(_ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    let time_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let buffer = translated_byte_buffer(current_user_token(), _ts as *const u8, core::mem::size_of::<TimeVal>());
    let mut time_value_ptr = &time_val as *const TimeVal as *const u8;
    for byte in buffer {
        for b in byte {
            unsafe {
                *b = *time_value_ptr;
                time_value_ptr = time_value_ptr.add(1);
            }
        }
    }
    0
}

/// YOUR JOB: Finish sys_task_info to pass testcases
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TaskInfo`] is splitted by two pages ?
pub fn sys_task_info(_ti: *mut TaskInfo) -> isize {
    trace!("kernel: sys_task_info");
    if _ti.is_null() {
        return -1;
    }
    let buffer = translated_byte_buffer(current_user_token(), _ti as *const u8, core::mem::size_of::<TaskInfo>());
    
    let task_info = TaskInfo {
        status: TaskStatus::Running,
        syscall_times: get_syscall_times(), 
        time: get_time_ms() - get_time_first_called(), 
    };

    let mut task_info_ptr = &task_info as *const TaskInfo as *const u8;
    for byte in buffer {
        for b in byte {
            unsafe {
                *b = *task_info_ptr;
                task_info_ptr = task_info_ptr.add(1);
            }
        }
    }

    0

}


// YOUR JOB: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap");
    // return -1;
    if start % PAGE_SIZE != 0 {
        return -1;
    }

    if port & !0x7 != 0 || port & 0x7 == 0 {
        return -1;
    }
    
    let mut permission = MapPermission::U;
    if (port & 0x1) != 0 { permission |= MapPermission::R; }
    if (port & 0x2) != 0 { permission |= MapPermission::W; }
    if (port & 0x4) != 0 { permission |= MapPermission::X; }
    let page_count = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    let memory_set = get_app_memory_set();
    for i in 0..page_count {
        let vpa = VirtAddr(start + i * PAGE_SIZE);
        unsafe {
            match (*memory_set).translate(vpa.into()) {
                Some(pte) => {
                    if pte.is_valid() {
                        return -1;
                    }
                }
                None => {}
            }
        }

    }
    unsafe {
        (*memory_set).insert_framed_area(start.into(), (start + len).into(), permission);
    }
    0
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
    if start % PAGE_SIZE != 0 {
        return -1;
    }
    let page_count = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    let memory_set = get_app_memory_set();
    for i in 0..page_count {
        let vpa = VirtAddr(start + i * PAGE_SIZE);
        unsafe {
            match (*memory_set).translate(vpa.into()) {
                Some(pte) => {
                    if !pte.is_valid() {
                        return -1;
                    } 
                }
                None => {}
            }
        }
    }
    unsafe{
        (*memory_set).pop(VirtAddr::from(start).into());
    }
    0

}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
