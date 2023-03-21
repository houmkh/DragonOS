use core::mem::{self, MaybeUninit};

use alloc::{sync::Arc, vec::Vec};

use crate::{
    arch::interrupt::{cli, sti},
    libs::spinlock::SpinLock,
    syscall::SystemError,
};

const MAX_SOFTIRQ_NUM: u64 = 64;
const MAX_LOCK_TRIAL_TIME: u64 = 50;
lazy_static! {
    pub static ref TRAP_VECTORS: SpinLock<Trap> = SpinLock::new(Trap::new());
}
/// 软中断向量号码
#[allow(dead_code)]
#[repr(u8)]
pub enum TrapNumber {
    TIMER = 0,        //时钟软中断信号
    VideoRefresh = 1, //帧缓冲区刷新软中断
}

bitflags! {
    pub struct VecStatus:u64{
        const BASE_STATUS = 1;
    }

}
impl VecStatus {
    /// @brief 清除指定位
    ///
    /// @param cl_bit 需要清除的位对应的值
    ///
    /// @param target 被操作的数
    pub fn clear_bit(cl_bit: u64, target: u64) -> u64 {
        let num = VecStatus::from_bits_truncate(cl_bit);
        let mut res = VecStatus::from_bits_truncate(target);
        res.remove(num);
        return res.bits();
    }

    /// @brief 清除指定位
    ///
    /// @param cl_bit 需要清除的位对应的值
    ///
    /// @param target 被操作的数
    pub fn set_bit(st_bit: u64, target: u64) -> u64 {
        let num = VecStatus::from_bits_truncate(st_bit);
        let mut res = VecStatus::from_bits_truncate(target);
        res.insert(num);
        return res.bits();
    }
}
pub trait TrapVec: Send + Sync {
    fn run(&self);
}

pub struct Trap {
    pending: u64,
    running: u64,
    table: [Option<Arc<dyn TrapVec>>; MAX_SOFTIRQ_NUM as usize],
}
impl Trap {
    fn new() -> Trap {
        let mut data: [MaybeUninit<Option<Arc<dyn TrapVec>>>; MAX_SOFTIRQ_NUM as usize] =
            unsafe { MaybeUninit::uninit().assume_init() };
        for elem in &mut data[..] {
            elem.write(None);
        }
        let data: [Option<Arc<dyn TrapVec>>; MAX_SOFTIRQ_NUM as usize] = unsafe {
            mem::transmute::<_, [Option<Arc<dyn TrapVec>>; MAX_SOFTIRQ_NUM as usize]>(data)
        };

        return Trap {
            pending: 0,
            running: 0,
            table: data,
        };
    }

    /// @brief 注册软中断向量
    ///
    /// @param trap_num 中断向量号
    ///
    /// @param hanlder 中断函数对应的结构体
    pub fn register_trap(
        &mut self,
        trap_num: u32,
        hanlder: Option<Arc<dyn TrapVec>>,
    ) -> Result<i32, SystemError> {
        // let self = &mut TRAP_VECTORS.lock();
        // 判断该软中断向量是否已经被注册
        if hanlder.is_none() || self.table[trap_num as usize].is_some() {
            return Err(SystemError::EINVAL);
        }
        self.table[trap_num as usize] = hanlder;

        // 将对应位置的running置0，pending置1
        self.running = VecStatus::clear_bit(trap_num as u64, self.running);
        self.pending = VecStatus::set_bit(trap_num as u64, self.pending);

        return Ok(0);
    }

    /// @brief 解注册软中断向量
    ///
    /// @param irq_num 中断向量号码   
    pub fn unregister_trap(&mut self, trap_num: u32) {
        // 将软中断向量清空
        self.table[trap_num as usize] = None;

        // 将对应位置的pending和runing都置0
        self.running = VecStatus::clear_bit(trap_num as u64, self.running);
        self.pending = VecStatus::clear_bit(trap_num as u64, self.pending);
    }

    pub fn do_trap(&mut self) {
        sti();
        if self.pending == 0 {
            return;
        }
        for softirq_num in 0..MAX_SOFTIRQ_NUM {
            if self.table[softirq_num as usize].is_none() {
                continue;
            }
            // 将running对应的位置1，pending对应的位置0,并执行函数
            self.running = VecStatus::set_bit(softirq_num, self.running);
            self.pending = VecStatus::clear_bit(softirq_num, self.pending);
            self.table[softirq_num as usize].as_ref().unwrap().run();
        }
        cli();
    }
}
