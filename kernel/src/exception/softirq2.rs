use core::mem::{self, MaybeUninit};

use alloc::sync::Arc;
use num_traits::FromPrimitive;

use crate::{
    arch::interrupt::{cli, sti},
    include::bindings::bindings::timer_jiffies,
    kdebug,
    libs::spinlock::SpinLock,
    syscall::SystemError,
};

const MAX_SOFTIRQ_NUM: u64 = 64;
const MAX_LOCK_TRIAL_TIME: u64 = 50;
lazy_static! {
    pub static ref SOFTIRQ_VECTORS: Softirq = Softirq::new();
}
/// 软中断向量号码
#[allow(dead_code)]
#[repr(u8)]
#[derive(FromPrimitive, Copy, Clone)]
pub enum SoftirqNumber {
    /// 时钟软中断信号
    TIMER = 0,
    VideoRefresh = 1, //帧缓冲区刷新软中断
}

impl From<u64> for SoftirqNumber {
    fn from(value: u64) -> Self {
        return <Self as FromPrimitive>::from_u64(value).unwrap();
    }
}

bitflags! {
    #[derive(Default)]
    pub struct VecStatus: u64 {
        const TIMER = 1 << SoftirqNumber::TIMER as u64;
        const VIDEO_REFRESH = 1 << SoftirqNumber::VideoRefresh as u64;
    }

}

impl From<SoftirqNumber> for VecStatus {
    fn from(value: SoftirqNumber) -> Self {
        return Self::from_bits_truncate(value as u64);
    }
}

pub trait SoftirqVec: Send + Sync {
    fn run(&self);
}

pub struct Softirq {
    pending: SpinLock<VecStatus>,
    running: SpinLock<VecStatus>,
    table: SpinLock<[Option<Arc<dyn SoftirqVec>>; MAX_SOFTIRQ_NUM as usize]>,
}
impl Softirq {
    fn new() -> Softirq {
        let mut data: [MaybeUninit<Option<Arc<dyn SoftirqVec>>>; MAX_SOFTIRQ_NUM as usize] =
            unsafe { MaybeUninit::uninit().assume_init() };
        for elem in &mut data[..] {
            elem.write(None);
        }
        let data: [Option<Arc<dyn SoftirqVec>>; MAX_SOFTIRQ_NUM as usize] = unsafe {
            mem::transmute::<_, [Option<Arc<dyn SoftirqVec>>; MAX_SOFTIRQ_NUM as usize]>(data)
        };

        return Softirq {
            pending: SpinLock::new(VecStatus::default()),
            running: SpinLock::new(VecStatus::default()),
            table: SpinLock::new(data),
        };
    }

    /// @brief 注册软中断向量
    ///
    /// @param softirq_num 中断向量号
    ///
    /// @param hanlder 中断函数对应的结构体
    pub fn register_softirq(
        &self,
        softirq_num: SoftirqNumber,
        handler: Arc<dyn SoftirqVec>,
    ) -> Result<i32, SystemError> {
        // kdebug!("register_softirq {:?}", softirq_num as u64);

        // let self = &mut SOFTIRQ_VECTORS.lock();
        // 判断该软中断向量是否已经被注册
        let table_guard = &mut self.table.lock();
        if table_guard[softirq_num as usize].is_some() {
            kdebug!("register_softirq failed");

            return Err(SystemError::EINVAL);
        }
        table_guard[softirq_num as usize] = Some(handler);

        // 将对应位置的running置0
        self.running.lock().set(VecStatus::from(softirq_num), false);
        kdebug!("register_softirq successfully, softirq_num = {:?}", softirq_num as u64);

        return Ok(0);
    }

    /// @brief 解注册软中断向量
    ///
    /// @param irq_num 中断向量号码   
    pub fn unregister_softirq(&self, softirq_num: SoftirqNumber) {
        kdebug!("unregister_softirq");
        let table_guard = &mut self.table.lock();
        // 将软中断向量清空
        table_guard[softirq_num as usize] = None;

        // 将对应位置的pending和runing都置0
        self.running.lock().set(VecStatus::from(softirq_num), false);
        self.pending.lock().set(VecStatus::from(softirq_num), false);
    }

    pub fn do_softirq(&self) {
        kdebug!("do_softirq begin,timer_jif = {:?}", timer_jiffies);
        // sti();
        kdebug!("do_softirq sti");
        // FIXME 尝试中断
        match self.pending.try_lock() {
            Ok(mut pending_guard) => {
                kdebug!("do_softirq self.pending.lock()");

                if pending_guard.is_empty() {
                    kdebug!("do_softirq self.pending.is_empty()");
                    // cli();
                    return;
                }
                match self.table.try_lock() {
                    Ok(mut v) => {
                        // kdebug!("do_softirq lock successfully");
                        let table_guard = &mut v;

                        for softirq_num in 0..MAX_SOFTIRQ_NUM {
                            if table_guard[softirq_num as usize].is_none() {
                                continue;
                            }
                            // 将running对应的位置1，pending对应的位置0,并执行函数
                            self.running
                                .lock()
                                .set(VecStatus::from(SoftirqNumber::from(softirq_num)), true);
                            pending_guard
                                .set(VecStatus::from(SoftirqNumber::from(softirq_num)), false);

                            table_guard[softirq_num as usize].as_ref().unwrap().run();

                            // self.running
                            //     .lock()
                            //     .set(VecStatus::from(SoftirqNumber::from(softirq_num)), false);
                            // pending_guard
                            //     .set(VecStatus::from(SoftirqNumber::from(softirq_num)), true);
                        }
                        // cli();
                        kdebug!("do_softirq successfully");
                        return;
                    }
                    Err(_) => return,
                }
            }
            Err(_) => return,
        }
    }

    pub fn raise_softirq(&self, softirq_num: SoftirqNumber) {
        // kdebug!("raise_softirq begin");
        for _ in 0..10 {
            match self.pending.try_lock() {
                Ok(mut pending_guard) => {
                    pending_guard.set(VecStatus::from(softirq_num), true);
                    // kdebug!("raise_softirq successfully");
                    return;
                }
                Err(_) => return,
            }
        }
    }
}

// ======= 以下为给C提供的接口 =======
#[no_mangle]
pub extern "C" fn rs_raise_softirq(softirq_num: u32) {
    SOFTIRQ_VECTORS.raise_softirq(SoftirqNumber::from(softirq_num as u64));
}

#[no_mangle]
pub extern "C" fn rs_unregister_softirq(softirq_num: u32) {
    SOFTIRQ_VECTORS.unregister_softirq(SoftirqNumber::from(softirq_num as u64));
}

#[no_mangle]
pub extern "C" fn rs_do_softirq() {
    SOFTIRQ_VECTORS.do_softirq();
}

#[no_mangle]
pub extern "C" fn rs_clear_softirq_pending(softirq_num: u32) {
    SOFTIRQ_VECTORS.pending.lock().set(
        VecStatus::from(SoftirqNumber::from(softirq_num as u64)),
        false,
    );
}
