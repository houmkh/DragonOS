use core::ptr::null_mut;

use alloc::{boxed::Box, collections::LinkedList};

use crate::{
    arch::{asm::current::current_pcb, sched::sched},
    include::bindings::bindings::PROC_RUNNING,
    kdebug, kinfo,
    libs::spinlock::{SpinLock, SpinLockGuard},
};

const MAX_TIMEOUT: i64 = i64::MAX;
pub static timer_jiffies: i64 = 0;
lazy_static! {
    pub static ref TIMER_LIST: SpinLock<LinkedList<Box<TimerFuncT>>> =
        SpinLock::new(LinkedList::default());
}

// pub struct TimerFuncData {
//     _data: [u8; 0],
//     _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
// }
// 定时器类型
pub struct TimerFuncT {
    pub expire_jiffies: u64,
    // pub func: ::core::option::Option<unsafe extern "C" fn(data: *mut TimerFuncData)>,
    // pub data: *mut TimerFuncData,
    // FIXME 解决指针unsafely问题
    pub func: ::core::option::Option<unsafe extern "C" fn(data: *mut core::ffi::c_void)>,
    // pub data: *mut core::ffi::c_void,
}
impl Default for TimerFuncT {
    fn default() -> Self {
        TimerFuncT {
            expire_jiffies: 0,
            func: None,
            // data: null_mut(),
        }
    }
}

impl TimerFuncT {
    pub fn new() -> TimerFuncT {
        TimerFuncT {
            ..Default::default()
        }
    }
    pub fn timer_func_init_ms(
        func: ::core::option::Option<unsafe extern "C" fn(data: *mut core::ffi::c_void)>,
        data: *mut ::core::ffi::c_void,
        expire_jiffies_ms: u64,
    ) -> Box<TimerFuncT> {
        let timer_func_t: Box<TimerFuncT> = Box::new(TimerFuncT {
            expire_jiffies: expire_jiffies_ms,
            func: func,
        });
        return timer_func_t;
    }

    pub fn timer_func_init_us(
        func: ::core::option::Option<unsafe extern "C" fn(data: *mut core::ffi::c_void)>,
        data: *mut ::core::ffi::c_void,
        expire_jiffies_us: u64,
    ) -> Box<TimerFuncT> {
        let timer_func_t: Box<TimerFuncT> = Box::new(TimerFuncT {
            expire_jiffies: expire_jiffies_us,
            func: func,
        });
        return timer_func_t;
    }
}

// FIXME 这个函数感觉没大用
pub extern "C" fn timer_init() {
    // BUG 测试list是否工作
    let temp: Box<TimerFuncT> = Box::new(TimerFuncT {
        expire_jiffies: 5,
        ..Default::default()
    });
    let timer_list: &mut SpinLockGuard<LinkedList<Box<TimerFuncT>>> = &mut TIMER_LIST.lock();
    timer_list.push_back(temp);
    if timer_list.len() == 1 {
        kinfo!("test done");
    }
    kdebug!("timer_init successfully");
}

// 根据定时器结束时间，将他插入正确的位置
pub fn push_timer_func(timer_func: Box<TimerFuncT>) {
    let timer_list: &mut SpinLockGuard<LinkedList<Box<TimerFuncT>>> = &mut TIMER_LIST.lock();

    // 链表为空，则直接插入
    if timer_list.is_empty() {
        timer_list.push_back(timer_func);
        return;
    }

    // 筛选出比timer_func晚结束的定时器
    let mut later_timer_funcs: LinkedList<Box<TimerFuncT>> = timer_list
        .drain_filter(|x| x.expire_jiffies > timer_func.expire_jiffies)
        .collect();

    // 插入timer_func定时器
    timer_list.push_back(timer_func);
    timer_list.append(&mut later_timer_funcs);
}

pub fn schedule_timeout_ms(timeout: i64) -> Result<i64, i64> {
    if timeout == MAX_TIMEOUT {
        sched();
        return Ok(MAX_TIMEOUT);
    } else if timeout < 0 {
        kdebug!("timeout can't less than 0");
        return Err(-1);
    } else {
        // FIXME 调用参数要修改
        let timer_func: Box<TimerFuncT> =
            TimerFuncT::timer_func_init_ms(None, null_mut(), timeout as u64);
        push_timer_func(timer_func);
        current_pcb().state &= (!PROC_RUNNING) as u64;
        sched();
        // FIXME why?
        let ret_timeout: i64 = timeout - timer_jiffies;
        if ret_timeout < 0 {
            return Ok(0);
        } else {
            return Ok(ret_timeout);
        }
    }
}
