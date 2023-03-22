use core::{ffi::c_void, ptr::null_mut};

use alloc::{
    boxed::Box,
    collections::LinkedList,
    sync::{Arc, Weak},
};

use crate::{
    arch::{asm::current::current_pcb, sched::sched, interrupt::{cli, sti}},
    exception::softirq2::{TrapNumber, TrapVec, TRAP_VECTORS},
    include::bindings::bindings::{process_control_block, process_wakeup, PROC_RUNNING},
    kdebug,
    libs::spinlock::{SpinLock, SpinLockGuard},
    syscall::SystemError,
};

const MAX_TIMEOUT: i64 = i64::MAX;
const TIMER_RUN_CYCLE_THRESHOLD: usize = 20;
pub static timer_jiffies: i64 = 0;

lazy_static! {
    pub static ref TIMER_LIST: SpinLock<LinkedList<Arc<Timer>>> = SpinLock::new(LinkedList::new());
}

/// 定时器要执行的函数的特征
pub trait TimerFunction: Send + Sync {
    fn run(&mut self);
}

/// WakeUpHelper函数对应的结构体
pub struct WakeUpHelper {
    pcb: &'static mut process_control_block,
}

impl WakeUpHelper {
    pub fn new(pcb: &'static mut process_control_block) -> Box<WakeUpHelper> {
        return Box::new(WakeUpHelper { pcb });
    }
}

impl TimerFunction for WakeUpHelper {
    fn run(&mut self) {
        unsafe {
            process_wakeup(self.pcb);
        }
    }
}

pub struct Timer(SpinLock<InnerTimer>);

impl Timer {
    /// @brief 创建一个定时器（单位：ms）
    ///
    /// @param timer_func 定时器需要执行的函数对应的结构体
    ///
    /// @param expire_jiffies 定时器结束时刻
    ///
    /// @return 定时器结构体
    pub fn new(timer_func: Box<dyn TimerFunction>, expire_jiffies: u64) -> Arc<Self> {
        let result: Arc<Timer> = Arc::new(Timer(SpinLock::new(InnerTimer {
            expire_jiffies,
            timer_func,
            self_ref: Weak::default(),
        })));

        result.0.lock().self_ref = Arc::downgrade(&result);

        return result;
    }

    /// @brief 将定时器插入到定时器链表中
    pub fn activate(&self) {
        let timer_list = &mut TIMER_LIST.lock();
        let inner_guard = self.0.lock();
        // 链表为空，则直接插入
        if timer_list.is_empty() {
            // FIXME push_timer
            timer_list.push_back(inner_guard.self_ref.upgrade().unwrap());
            return;
        }

        // 筛选出比timer_func晚结束的定时器
        let mut later_timer_funcs = timer_list
            .drain_filter(|x| x.0.lock().expire_jiffies > inner_guard.expire_jiffies)
            .collect();

        // 将定时器插入到链表中
        // FIXME push_timer
        // timer_list.push_back(self);
        timer_list.append(&mut later_timer_funcs);
    }

    #[inline]
    fn run(&self) {
        self.0.lock().timer_func.run();
    }
}

/// 定时器类型
pub struct InnerTimer {
    /// 定时器结束时刻
    pub expire_jiffies: u64,
    /// 定时器需要执行的函数结构体
    pub timer_func: Box<dyn TimerFunction>,
    // FIXME self_ref
    self_ref: Weak<Timer>,
}

pub struct DoTimerSoftirq;
impl TrapVec for DoTimerSoftirq {
    fn run(&self) {
        // 最多只处理TIMER_RUN_CYCLE_THRESHOLD个计时器
        for _ in 0..TIMER_RUN_CYCLE_THRESHOLD {
            let timer_list = &mut TIMER_LIST.lock();

            if timer_list.is_empty() {
                break;
            }

            if timer_list.front().unwrap().0.lock().expire_jiffies <= timer_jiffies as u64 {
                let timer = timer_list.pop_front().unwrap();
                drop(timer_list);
                timer.run();
            }
        }
    }
}
impl DoTimerSoftirq {
    pub fn new() -> DoTimerSoftirq {
        return DoTimerSoftirq {};
    }
}

/// @brief 初始化timer模块
#[no_mangle]
pub fn timer_init() {
    // FIXME 调用register_trap
    let do_timer_softirq = Arc::new(DoTimerSoftirq::new());
    TRAP_VECTORS
        .lock()
        .register_trap(TrapNumber::TIMER, do_timer_softirq)
        .expect("Failed to register timer softirq");
}

/// 计算接下来n毫秒对应的定时器时间片
pub fn next_n_ms_timer_jiffies(expire_ms: u64) -> u64 {
    timer_jiffies as u64 + 1000 * (expire_ms)
}
/// 计算接下来n微秒对应的定时器时间片
pub fn next_n_us_timer_jiffies(expire_us: u64) -> u64 {
    timer_jiffies as u64 + (expire_us)
}

/// @brief 让pcb休眠timeout个jiffies
///
/// @param timeout 需要休眠的时间(单位：jiffies)
///
/// @return Ok(i64) 剩余需要休眠的时间(单位：jiffies)
///
/// @return Err(SystemError) 错误码
pub fn schedule_timeout(mut timeout: i64) -> Result<i64, SystemError> {
    if timeout == MAX_TIMEOUT {
        sched();
        return Ok(MAX_TIMEOUT);
    } else if timeout < 0 {
        kdebug!("timeout can't less than 0");
        return Err(SystemError::EINVAL);
    } else {
        // 禁用中断，防止在这段期间发生调度，造成死锁
        cli();
        timeout += timer_jiffies;
        let timer = Timer::new(WakeUpHelper::new(current_pcb()), timeout as u64);
        timer.activate();
        current_pcb().state &= (!PROC_RUNNING) as u64;
        sti();

        sched();
        let time_remaining: i64 = timeout - timer_jiffies;
        if time_remaining >= 0 {
            // 被提前唤醒，返回剩余时间
            return Ok(time_remaining);
        } else {
            return Ok(0);
        }
    }
}
