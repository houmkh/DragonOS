use core::{ffi::c_void, ptr::null_mut};

use alloc::{collections::LinkedList, rc::Weak, sync::Arc};

use crate::{
    arch::{asm::current::current_pcb, sched::sched},
    exception::softirq2::TrapVec,
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
    fn run(&self);
}
pub struct Handler {
    handler: Arc<LockWakeUpHelper>,
}
impl Handler {
    fn new() -> Arc<Self> {
        let h = Arc::new(LockWakeUpHelper(SpinLock::new(
            WakeUpHelper::new(null_mut()).unwrap(),
        )));
        let res = Arc::new(Handler { handler: h });
        return res;
    }
}
pub struct LockWakeUpHelper(SpinLock<WakeUpHelper>);
/// WakeUpHelper函数对应的结构体
pub struct WakeUpHelper {
    pcb: Option<process_control_block>,
    // FIXME self_ref
    // self_ref: Weak<LockWakeUpHelper>,
}
impl WakeUpHelper {
    pub fn new(in_pcb: *mut process_control_block) -> Option<WakeUpHelper> {
        if in_pcb == null_mut() {
            return None;
        } else {
            return Some(WakeUpHelper {
                pcb: Some(unsafe { *in_pcb }),
                // self_ref: Default::default(),
            });
        }
    }
}

impl TimerFunction for WakeUpHelper {
    fn run(&self) {
        match self.pcb {
            None => {
                kdebug!("pcb can't be none");
                return;
            }
            Some(mut pcb) => unsafe {
                process_wakeup(&mut pcb);
            },
        }
    }
}

/// 定时器类型
pub struct Timer {
    /// 定时器结束时刻
    pub expire_jiffies: u64,
    /// 定时器需要执行的函数结构体
    pub timer_func: Arc<dyn TimerFunction>,
}
impl Timer {
    /// @brief 创建一个定时器（单位：ms）
    ///
    /// @param timer_func 定时器需要执行的函数对应的结构体
    ///
    /// @param expire_jiffies_ms 定时器结束时刻
    ///
    /// @return 定时器结构体
    pub fn create_timer_ms(
        timer_func: Arc<dyn TimerFunction>,
        expire_jiffies_ms: u64,
    ) -> Arc<Timer> {
        return Arc::new(Timer {
            expire_jiffies: expire_jiffies_ms,
            timer_func: timer_func,
        });
    }

    /// @brief 创建一个定时器（单位：us）
    ///
    /// @param timer_func 定时器需要执行的函数对应的结构体
    ///
    /// @param expire_jiffies_ms 定时器结束时刻
    ///
    /// @return 定时器结构体
    pub fn create_timer_us(
        timer_func: Arc<dyn TimerFunction>,
        expire_jiffies_us: u64,
    ) -> Arc<Timer> {
        return Arc::new(Timer {
            expire_jiffies: expire_jiffies_us,
            timer_func: timer_func,
        });
    }

    /// @brief 将定时器插入到定时器链表中
    pub fn push_timer(&self) {
        let timer_list: &mut SpinLockGuard<LinkedList<Arc<Timer>>> = &mut TIMER_LIST.lock();
        // 链表为空，则直接插入
        if timer_list.is_empty() {
            // FIXME push_timer
            // timer_list.push_back(self);
            return;
        }

        // 筛选出比timer_func晚结束的定时器
        let mut later_timer_funcs: LinkedList<Arc<Timer>> = timer_list
            .drain_filter(|x| x.expire_jiffies > self.expire_jiffies)
            .collect();

        // 将定时器插入到链表中
        // FIXME push_timer
        // timer_list.push_back(self);
        timer_list.append(&mut later_timer_funcs);
    }

    /// @brief 让pcb休眠timeout时间
    ///
    /// @param timeout 需要休眠的时间
    ///
    /// @return Ok(i64) 剩余需要休眠的时间
    ///
    /// @return Err(SystemError) 错误码
    pub fn schedule_timeout_ms(&self, timeout: i64) -> Result<i64, SystemError> {
        if timeout == MAX_TIMEOUT {
            sched();
            return Ok(MAX_TIMEOUT);
        } else if timeout < 0 {
            kdebug!("timeout can't less than 0");
            return Err(SystemError::EINVAL);
        } else {
            self.push_timer();
            current_pcb().state &= (!PROC_RUNNING) as u64;
            sched();
            let sched_clock: i64 = timer_jiffies;
            let time_remaining: i64 = timer_jiffies - sched_clock;
            if time_remaining >= timeout {
                // 返回剩余时间
                return Ok(time_remaining);
            } else {
                return Ok(0);
            }
        }
    }
}

/// @brief 处理时间软中断
///
/// @param data
#[no_mangle]
pub extern "C" fn do_timer_softirq(_data: *mut c_void) {
    let timer_list = &mut TIMER_LIST.lock();
    // 最多只处理TIMER_RUN_CYCLE_THRESHOLD个计时器
    for pos in 0..TIMER_RUN_CYCLE_THRESHOLD {
        if pos < timer_list.len()
            && timer_list.front().unwrap().expire_jiffies <= timer_jiffies.try_into().unwrap()
        {
            let timer = timer_list.pop_front().unwrap();
            timer.timer_func.run();
        } else {
            break;
        }
    }
}

pub struct DoTimerSoftirq {}
impl TrapVec for DoTimerSoftirq {
    fn run(&self) {
        do_timer_softirq(null_mut());
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
    // let do_timer_softirq = Some(Arc::new(DoTimerSoftirq::new()));
    // TRAP_VECTORS
    //     .lock()
    //     .register_trap(TrapNumber::TIMER, do_timer_softirq);
}
