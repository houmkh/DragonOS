use core::{arch::x86_64::_rdtsc, ptr::null_mut};

use alloc::sync::Arc;

use crate::{
    arch::{asm::current::current_pcb, sched::sched},
    include::bindings::bindings::{
        timespec, useconds_t, Cpu_tsc_freq, PF_NEED_SCHED, PROC_INTERRUPTIBLE,
    },
    syscall::SystemError,
};

use super::{
    timer::{Timer, WakeUpHelper},
    TimeSpec,
};

/// @brief 休眠指定时间（单位：纳秒）
///
/// @param sleep_time 指定休眠的时间
///
/// @return Ok(TimeSpec) 剩余休眠时间
///
/// @return Err(SystemError) 错误码
pub fn nano_sleep(sleep_time: TimeSpec) -> Result<TimeSpec, SystemError> {
    if sleep_time.tv_nsec < 0 || sleep_time.tv_nsec >= 1000000000 {
        return Err(SystemError::EINVAL);
    }
    // 对于小于500us的时间，使用spin/rdtsc来进行定时

    if sleep_time.tv_nsec < 500000 {
        let expired_tsc: u64 =
            unsafe { _rdtsc() + (sleep_time.tv_nsec as u64 * Cpu_tsc_freq) / 1000000000 };
        while unsafe { _rdtsc() } < expired_tsc {}
        return Ok(TimeSpec {
            tv_sec: 0,
            tv_nsec: 0,
        });
    }
    let handler = WakeUpHelper::new(current_pcb());
    if handler.is_some() {
        let nanosleep_handler: Arc<WakeUpHelper> = Arc::new(handler.unwrap());
        let timer = Timer::create_timer_us(nanosleep_handler, (sleep_time.tv_nsec / 1000) as u64);
        timer.push_timer();
        current_pcb().state = PROC_INTERRUPTIBLE as u64;
        current_pcb().flags |= PF_NEED_SCHED as u64;
        sched();

        // TODO: 增加信号唤醒的功能后，返回正确的剩余时间

        return Ok(TimeSpec {
            tv_sec: 0,
            tv_nsec: 0,
        });
    }
    return Err(SystemError::EINVAL);
}

/// @brief 休眠指定时间（单位：微秒）
///
///  @param usec 微秒
///
/// @return Ok(TimeSpec) 剩余休眠时间
///
/// @return Err(SystemError) 错误码
pub fn us_sleep(sleep_time: TimeSpec) -> Result<TimeSpec, SystemError> {
    match nano_sleep(sleep_time) {
        Ok(value) => return Ok(value),
        Err(err) => return Err(err),
    };
}

/// @brief 休眠指定时间（单位：纳秒）（提供给C的接口）
///
/// @param sleep_time 指定休眠的时间
///
/// @param rm_time 剩余休眠时间（传出参数）
///
/// @return Ok(i32) 0
///
/// @return Err(SystemError) 错误码
#[no_mangle]
pub extern "C" fn nano_sleep_c(
    sleep_time: timespec,
    rm_time: *mut timespec,
) -> Result<i32, SystemError> {
    let slt_spec = TimeSpec {
        tv_sec: sleep_time.tv_sec,
        tv_nsec: sleep_time.tv_nsec,
    };

    match nano_sleep(slt_spec) {
        Ok(value) => {
            if rm_time != null_mut() {
                unsafe {
                    (*rm_time).tv_sec = value.tv_sec;
                    (*rm_time).tv_nsec = value.tv_nsec;
                }
            }
            return Ok(0);
        }
        Err(err) => {
            return Err(err);
        }
    }
}

/// @brief 休眠指定时间（单位：微秒）（提供给C的接口）
///
///  @param usec 微秒
///
/// @return Ok(i32) 0
///
/// @return Err(SystemError) 错误码
#[no_mangle]
pub extern "C" fn us_sleep_c(usec: useconds_t) -> Result<i32, SystemError> {
    let sleep_time = TimeSpec {
        tv_sec: (usec / 1000000) as i64,
        tv_nsec: ((usec % 1000000) * 1000) as i64,
    };
    match us_sleep(sleep_time) {
        Ok(_) => return Ok(0),
        Err(err) => return Err(err),
    };
}
