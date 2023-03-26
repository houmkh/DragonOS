use core::mem::{self, MaybeUninit};

use alloc::sync::Arc;
use num_traits::FromPrimitive;

use crate::{
    arch::interrupt::{cli, sti},
    libs::spinlock::SpinLock,
    syscall::SystemError,
};

const MAX_SOFTIRQ_NUM: u64 = 64;
const MAX_LOCK_TRIAL_TIME: u64 = 50;
lazy_static! {
    pub static ref SOFTIRQ_VECTORS: SpinLock<Softirq> = SpinLock::new(Softirq::new());
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

impl From<SoftirqNumber> for VecStatus{
    fn from(value: SoftirqNumber) -> Self {
        return Self::from_bits_truncate(value as u64);
    }
}

pub trait SoftirqVec: Send + Sync {
    fn run(&self);
}

pub struct Softirq {
    pending: VecStatus,
    running: VecStatus,
    table: [Option<Arc<dyn SoftirqVec>>; MAX_SOFTIRQ_NUM as usize],
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
            pending: VecStatus::default(),
            running: VecStatus::default(),
            table: data,
        };
    }

    /// @brief 注册软中断向量
    ///
    /// @param softirq_num 中断向量号
    ///
    /// @param hanlder 中断函数对应的结构体
    pub fn register_softirq(
        &mut self,
        softirq_num: SoftirqNumber,
        handler: Arc<dyn SoftirqVec>,
    ) -> Result<i32, SystemError> {
        // let self = &mut SOFTIRQ_VECTORS.lock();
        // 判断该软中断向量是否已经被注册
        if self.table[softirq_num as usize].is_some() {
            return Err(SystemError::EINVAL);
        }
        self.table[softirq_num as usize] = Some(handler);

        // 将对应位置的running置0
        self.running.set(VecStatus::from(softirq_num), false);

        return Ok(0);
    }

    /// @brief 解注册软中断向量
    ///
    /// @param irq_num 中断向量号码   
    pub fn unregister_softirq(&mut self, softirq_num: SoftirqNumber) {
        // 将软中断向量清空
        self.table[softirq_num as usize] = None;

        // 将对应位置的pending和runing都置0
        self.running.set(VecStatus::from(softirq_num), false);
        self.pending.set(VecStatus::from(softirq_num), false);
    }

    pub fn do_softirq(&mut self) {
        sti();
        if self.pending.is_empty() {
            return;
        }
        for softirq_num in 0..MAX_SOFTIRQ_NUM {
            if self.table[softirq_num as usize].is_none() {
                continue;
            }
            // 将running对应的位置1，pending对应的位置0,并执行函数
            self.running.set(VecStatus::from(SoftirqNumber::from(softirq_num)), true);
            self.pending.set(VecStatus::from(SoftirqNumber::from(softirq_num)), false);

            self.table[softirq_num as usize].as_ref().unwrap().run();
        }
        cli();
    }

    pub fn raise_softirq(&mut self, softirq_num: SoftirqNumber) {
        self.pending.set(VecStatus::from(softirq_num), true);
    }
}

// ======= 以下为给C提供的接口 =======
#[no_mangle]
pub extern "C" fn raise_softirq_c(softirq_num: u32) {
    SOFTIRQ_VECTORS
        .lock()
        .raise_softirq(SoftirqNumber::from(softirq_num as u64));
}

#[no_mangle]
pub extern "C" fn unregister_softirq_c(softirq_num: u32) {
    SOFTIRQ_VECTORS
        .lock()
        .unregister_softirq(SoftirqNumber::from(softirq_num as u64));
}

#[no_mangle]
pub extern "C" fn do_softirq() {
    SOFTIRQ_VECTORS.lock().do_softirq();
}

#[no_mangle]
pub extern "C" fn clear_softirq_pending(softirq_num: u32) {
    SOFTIRQ_VECTORS.lock().pending.set(VecStatus::from(SoftirqNumber::from(softirq_num as u64)), false);
}
