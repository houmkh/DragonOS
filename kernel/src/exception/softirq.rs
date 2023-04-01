use core::{
    fmt::Debug,
    intrinsics::unlikely,
    mem::{self, MaybeUninit},
    ptr::null_mut,
    sync::atomic::{compiler_fence, Ordering},
};

use alloc::{boxed::Box, sync::Arc};
use num_traits::FromPrimitive;

use crate::{
    arch::{
        asm::{
            current::current_pcb,
            irqflags::{local_irq_restore, local_irq_save},
        },
        interrupt::{cli, sti},
    },
    include::bindings::bindings::MAX_CPU_NUM,
    kdebug,
    libs::rwlock::RwLock,
    smp::core::smp_get_processor_id,
    syscall::SystemError,
    time::timer::clock,
};

const MAX_SOFTIRQ_NUM: u64 = 64;
const MAX_LOCK_TRIAL_TIME: u64 = 50;
const MAX_SOFTIRQ_RESTART: i32 = 20;
// static mut CPU_PENDING: [VecStatus; MAX_CPU_NUM as usize] =
//     [VecStatus { bits: 0 }; MAX_CPU_NUM as usize];

static mut __CPU_PENDING: Option<Box<[VecStatus; MAX_CPU_NUM as usize]>> = None;
static mut __SORTIRQ_VECTORS: *mut Softirq = null_mut();

#[no_mangle]
pub extern "C" fn rs_softirq_init() {
    softirq_init().expect("softirq_init failed");
}

pub fn softirq_init() -> Result<(), SystemError> {
    unsafe {
        __SORTIRQ_VECTORS = Box::leak(Box::new(Softirq::new()));
        __CPU_PENDING = Some(Box::new([VecStatus::default(); MAX_CPU_NUM as usize]));
        let cpu_pending = __CPU_PENDING.as_mut().unwrap();
        for i in 0..MAX_CPU_NUM {
            cpu_pending[i as usize] = VecStatus::default();
        }
    }
    return Ok(());
}

#[inline(always)]
pub fn softirq_vectors() -> &'static mut Softirq {
    unsafe {
        return __SORTIRQ_VECTORS.as_mut().unwrap();
    }
}

#[inline(always)]
fn cpu_pending(cpu_id: usize) -> &'static mut VecStatus {
    unsafe {
        return &mut __CPU_PENDING.as_mut().unwrap()[cpu_id];
    }
}

/// 软中断向量号码
#[allow(dead_code)]
#[repr(u8)]
#[derive(FromPrimitive, Copy, Clone, Debug, PartialEq, Eq)]
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
        const TIMER = 1 << 0;
        const VIDEO_REFRESH = 1 << 1;
    }

}

impl From<SoftirqNumber> for VecStatus {
    fn from(value: SoftirqNumber) -> Self {
        return Self::from_bits_truncate(1 << (value as u64));
    }
}

pub trait SoftirqVec: Send + Sync + Debug {
    fn run(&self);
}

pub struct Softirq {
    // pending: SpinLock<VecStatus>,
    // running: SpinLock<VecStatus>,
    table: RwLock<[Option<Arc<dyn SoftirqVec>>; MAX_SOFTIRQ_NUM as usize]>,
    // local_cpu_pending: CpuPending,
}
impl Softirq {
    fn new() -> Softirq {
        let mut data: [MaybeUninit<Option<Arc<dyn SoftirqVec>>>; MAX_SOFTIRQ_NUM as usize] =
            unsafe { MaybeUninit::uninit().assume_init() };

        for i in 0..MAX_SOFTIRQ_NUM {
            data[i as usize] = MaybeUninit::new(None);
        }

        let data: [Option<Arc<dyn SoftirqVec>>; MAX_SOFTIRQ_NUM as usize] = unsafe {
            mem::transmute::<_, [Option<Arc<dyn SoftirqVec>>; MAX_SOFTIRQ_NUM as usize]>(data)
        };

        return Softirq {
            // pending: SpinLock::new(VecStatus::default()),
            // running: SpinLock::new(VecStatus::default()),
            table: RwLock::new(data),
            // local_cpu_pending: unsafe { mem::zeroed() },
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
        kdebug!("register_softirq softirq_num = {:?}", softirq_num as u64);

        // let self = &mut SOFTIRQ_VECTORS.lock();
        // 判断该软中断向量是否已经被注册
        let table_guard = self.table.upgradeable_read();
        if table_guard[softirq_num as usize].is_some() {
            kdebug!("register_softirq failed");

            return Err(SystemError::EINVAL);
        }
        let mut table_guard = table_guard.upgrade();
        table_guard[softirq_num as usize] = Some(handler);
        drop(table_guard);
        // 将对应位置的running置0
        // self.running.lock().set(VecStatus::from(softirq_num), false);
        kdebug!(
            "register_softirq successfully, softirq_num = {:?}",
            softirq_num as u64
        );
        compiler_fence(Ordering::SeqCst);
        return Ok(0);
    }

    /// @brief 解注册软中断向量
    ///
    /// @param irq_num 中断向量号码   
    pub fn unregister_softirq(&self, softirq_num: SoftirqNumber) {
        kdebug!("unregister_softirq softirq_num = {:?}", softirq_num as u64);
        let table_guard = &mut self.table.write();
        // 将软中断向量清空
        table_guard[softirq_num as usize] = None;
        drop(table_guard);
        // 将对应位置的pending和runing都置0
        // self.running.lock().set(VecStatus::from(softirq_num), false);
        // 将对应CPU的pending置0
        compiler_fence(Ordering::SeqCst);
        cpu_pending(smp_get_processor_id() as usize).set(VecStatus::from(softirq_num), false);
        compiler_fence(Ordering::SeqCst);
    }

    pub fn do_softirq(&self) {
        // TODO pcb的flags未修改
        // kdebug!("do_softirq begin");
        let end = clock() + 500 * 2;
        let cpu_id = smp_get_processor_id();
        let mut max_restart = MAX_SOFTIRQ_RESTART;
        loop {
            compiler_fence(Ordering::SeqCst);
            let pending = cpu_pending(cpu_id as usize).bits;
            cpu_pending(cpu_id as usize).bits = 0;
            compiler_fence(Ordering::SeqCst);
            // if pending != 0 {
            //     kdebug!("do_softirq pending = {:#018x}", pending);
            // }

            // kdebug!("table = {:?}", self.table.read().clone());
            // loop {}
            sti();
            for i in 0..MAX_SOFTIRQ_NUM {
                if pending & (1 << i) == 0 {
                    continue;
                }

                let table_guard = self.table.read();
                let softirq_func = table_guard[i as usize].clone();
                drop(table_guard);
                if softirq_func.is_none() {
                    if i == 1 {
                        kdebug!("do_softirq i = {:?} softirq_func is none", i)
                    }
                    continue;
                }
                if i == 1 {
                    kdebug!("do_softirq i = {:?}", i);
                }
                let prev_count = current_pcb().preempt_count;

                softirq_func.as_ref().unwrap().run();
                if unlikely(prev_count != current_pcb().preempt_count) {
                    kdebug!(
                        "entered softirq {:?} with preempt_count {:?},exited with {:?}",
                        i,
                        prev_count,
                        current_pcb().preempt_count
                    );
                    current_pcb().preempt_count = prev_count;
                }
            }
            cli();
            max_restart -= 1;
            compiler_fence(Ordering::SeqCst);
            if cpu_pending(cpu_id as usize).is_empty() {
                compiler_fence(Ordering::SeqCst);
                if clock() < end && max_restart > 0 {
                    continue;
                }
            } else {
                // TODO：当有softirqd时 唤醒它
                break;
            }
            compiler_fence(Ordering::SeqCst);
        }
        // kdebug!("do_softirq exited");
    }

    pub fn raise_softirq(&self, softirq_num: SoftirqNumber) {
        let mut flags = 0;
        local_irq_save(&mut flags);
        // kdebug!("raise_softirq begin");
        // for _ in 0..10 {
        //     match self.pending.try_lock() {
        //         Ok(mut pending_guard) => {
        //             pending_guard.set(VecStatus::from(softirq_num), true);
        //             // kdebug!("raise_softirq successfully");
        //             return;
        //         }
        //         Err(_) => return,
        //     }
        // }
        // kdebug!("raise_softirq softirq_num = {:?}", softirq_num as u64);
        kdebug!(" smp_get_processor_id()={}", smp_get_processor_id());
        if softirq_num == SoftirqNumber::TIMER {
            kdebug!("timer, smp_get_processor_id()={}", smp_get_processor_id());
            // kdebug!("raise_softirq softirq_num = {:?}", softirq_num as u64);
            // unsafe { CPU_PENDING[smp_get_processor_id() as usize] }.insert(VecStatus::TIMER);
            cpu_pending(smp_get_processor_id() as usize).insert(VecStatus::TIMER);
            // unsafe { CPU_PENDING[smp_get_processor_id() as usize] }.set(VecStatus::TIMER, true);
        } else {
            kdebug!("video, smp_get_processor_id()={}", smp_get_processor_id());
            // let vs = VecStatus::from_bits_truncate(1 << 1);
            // kdebug!("raise_softirq vs = {:#018x}", vs.bits);
            // unsafe { CPU_PENDING[smp_get_processor_id() as usize] }.insert(vs);

            cpu_pending(smp_get_processor_id() as usize).insert(VecStatus::VIDEO_REFRESH);
        }

        compiler_fence(Ordering::SeqCst);

        // CPU_PENDING[smp_get_processor_id() as usize].set(VecStatus::from(softirq_num), true);
        let bits = cpu_pending(smp_get_processor_id() as usize).bits();
        compiler_fence(Ordering::SeqCst);
        kdebug!("after raise_softirq [{softirq_num:?}], CPU_PENDING = {bits:#018x}");
        compiler_fence(Ordering::SeqCst);

        local_irq_restore(&flags);
        // kdebug!("raise_softirq exited");
    }
    pub fn clear_softirq_pending(&self, softirq_num: SoftirqNumber) {
        compiler_fence(Ordering::SeqCst);
        // CPU_PENDING[smp_get_processor_id() as usize].set(VecStatus::from(softirq_num), false);
        cpu_pending(smp_get_processor_id() as usize).remove(VecStatus::from(softirq_num));
        compiler_fence(Ordering::SeqCst);
    }
}

// ======= 以下为给C提供的接口 =======
#[no_mangle]
pub extern "C" fn rs_raise_softirq(softirq_num: u32) {
    softirq_vectors().raise_softirq(SoftirqNumber::from(softirq_num as u64));
}

#[no_mangle]
pub extern "C" fn rs_unregister_softirq(softirq_num: u32) {
    softirq_vectors().unregister_softirq(SoftirqNumber::from(softirq_num as u64));
}

#[no_mangle]
pub extern "C" fn rs_do_softirq() {
    softirq_vectors().do_softirq();
}

#[no_mangle]
pub extern "C" fn rs_clear_softirq_pending(softirq_num: u32) {
    softirq_vectors().clear_softirq_pending(SoftirqNumber::from(softirq_num as u64));
}
