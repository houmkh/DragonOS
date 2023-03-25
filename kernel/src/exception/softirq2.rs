use core::mem::{self, MaybeUninit};

use alloc::{sync::Arc};
use num_traits::{FromPrimitive};

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
    pub struct VecStatus:u64{
        const BASE_STATUS = 1;
    }

}
impl VecStatus {
    /// @brief 清除指定位
    ///
    /// @param cl it 需要清除的位对应的值
    pub fn clear_bit(&mut self, cl_bit: u64) {
        let num = VecStatus::from_bits_truncate(cl_bit);
        self.remove(num);
    }

    /// @brief 清除指定位
    ///
    /// @param cl_bit 需要清除的位对应的值
    pub fn set_bit(&mut self, st_bit: u64) {
        let num = VecStatus::from_bits_truncate(st_bit);
        self.insert(num);
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

        // 将对应位置的running置0，pending置1
        self.running.clear_bit(softirq_num as u64);
        self.pending.set_bit(softirq_num as u64);

        return Ok(0);
    }

    /// @brief 解注册软中断向量
    ///
    /// @param irq_num 中断向量号码   
    pub fn unregister_softirq(&mut self, softirq_num: SoftirqNumber) {
        // 将软中断向量清空
        self.table[softirq_num as usize] = None;

        // 将对应位置的pending和runing都置0
        self.running.clear_bit(softirq_num as u64);
        self.pending.clear_bit(softirq_num as u64);
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
            self.running.set_bit(softirq_num);
            self.pending.clear_bit(softirq_num);
            self.table[softirq_num as usize].as_ref().unwrap().run();
        }
        cli();
    }

    pub fn raise_softirq(&mut self, softirq_num: SoftirqNumber) {
        self.pending.set_bit(softirq_num as u64);
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
    SOFTIRQ_VECTORS.lock().pending.clear_bit(softirq_num as u64);
}
