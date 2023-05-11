use alloc::{boxed::Box, sync::Arc};
use core::{intrinsics::unlikely, ptr::null_mut, time};

use crate::{
    arch::CurrentIrqArch, driver::timers::rtc::rtc::RtcTime, exception::InterruptArch, kdebug,
    libs::rwlock::RwLock, sched::rt, time::TimeSpec,
};

use super::{
    clocksource::{clocksource_cyc2ns, clocksource_default_clock, Clocksource, CycleNum, HZ},
    NSEC_PER_SEC,
};

pub const NTP_INTERVAL_FREQ: u64 = HZ;
pub const NTP_INTERVAL_LENGTH: u64 = NSEC_PER_SEC as u64 / NTP_INTERVAL_FREQ;
pub const NTP_SCALE_SHIFT: u32 = 32;

pub static TIMEKEEPING_SUSPENDED: RwLock<bool> = RwLock::new(false);
static mut __TIMEKEEPER: *mut Timekeeper = null_mut();
pub struct Timekeeper(RwLock<TimekeeperData>);
pub struct TimekeeperData {
    /// 用于计时的当前时钟源。
    clock: Option<Arc<dyn Clocksource>>,
    /// 当前时钟源的移位值。
    shift: i32,
    /// 一个NTP间隔中的时钟周期数。
    cycle_interval: CycleNum,
    /// 一个NTP间隔中时钟移位的纳秒数。
    xtime_interval: u64,
    ///
    xtime_remainder: i64,
    /// 每个NTP间隔累积的原始纳米秒
    raw_interval: i64,
    /// 时钟移位纳米秒余数
    xtime_nsec: u64,
    /// 积累时间和ntp时间在ntp位移纳秒量上的差距
    ntp_error: i64,
    /// 用于转换时钟偏移纳秒和ntp偏移纳秒的偏移量
    ntp_error_shift: i32,
    /// NTP调整时钟乘法器
    mult: u32,
    raw_time: TimeSpec,
    wall_to_monotonic: TimeSpec,
    total_sleep_time: TimeSpec,
    xtime: TimeSpec,
}
impl TimekeeperData {
    pub fn new() -> Self {
        Self {
            clock: None,
            shift: Default::default(),
            cycle_interval: CycleNum(0),
            xtime_interval: Default::default(),
            xtime_remainder: Default::default(),
            raw_interval: Default::default(),
            xtime_nsec: Default::default(),
            ntp_error: Default::default(),
            ntp_error_shift: Default::default(),
            mult: Default::default(),
            xtime: TimeSpec {
                tv_nsec: 0,
                tv_sec: 0,
            },
            wall_to_monotonic: TimeSpec {
                tv_nsec: 0,
                tv_sec: 0,
            },
            total_sleep_time: TimeSpec {
                tv_nsec: 0,
                tv_sec: 0,
            },
            raw_time: TimeSpec {
                tv_nsec: 0,
                tv_sec: 0,
            },
        }
    }
}
impl Timekeeper {
    pub fn timekeeper_setup_internals(&self, clock: Arc<dyn Clocksource>) {
        let timekeeper = &mut self.0.write();
        // 更新clock
        let mut clock_data = clock.clocksource_data();
        clock_data.watchdog_last = clock.read();
        if clock.update_clocksource_data(clock_data).is_err() {
            kdebug!("timekeeper_setup_internals:update_clocksource_data run failed");
        }
        timekeeper.clock.replace(clock.clone());

        let clock_data = clock.clocksource_data();
        let mut temp = NTP_INTERVAL_LENGTH << clock_data.shift;
        let ntpinterval = temp;
        temp += (clock_data.mult / 2) as u64;
        // do div

        timekeeper.cycle_interval = CycleNum(temp);
        timekeeper.xtime_interval = temp * clock_data.mult as u64;
        timekeeper.xtime_remainder = (ntpinterval - timekeeper.xtime_interval) as i64;
        timekeeper.raw_interval = (timekeeper.xtime_interval >> clock_data.shift) as i64;
        timekeeper.xtime_nsec = 0;
        timekeeper.shift = clock_data.shift as i32;

        timekeeper.ntp_error = 0;
        timekeeper.ntp_error_shift = (NTP_SCALE_SHIFT - clock_data.shift) as i32;

        timekeeper.mult = clock_data.mult;
    }

    pub fn timekeeping_get_ns(&self) -> u64 {
        let timekeeper = self.0.read();
        let clock = timekeeper.clock.clone().unwrap();
        let clock_now = clock.read();
        let clcok_data = clock.clocksource_data();
        let clock_delta = clock_now.div(clcok_data.watchdog_last).data() & clcok_data.mask.bits();
        return clocksource_cyc2ns(CycleNum(clock_delta), clcok_data.mult, clcok_data.shift);
    }
}
pub fn timekeeper() -> &'static mut Timekeeper {
    return unsafe { __TIMEKEEPER.as_mut().unwrap() };
}

pub fn timekeeper_init() {
    unsafe { __TIMEKEEPER = Box::leak(Box::new(Timekeeper(RwLock::new(TimekeeperData::new())))) };
}

pub fn getnstimeofday() -> TimeSpec {
    let mut nsecs: u64 = 0;
    let mut xtime = TimeSpec {
        tv_nsec: 0,
        tv_sec: 0,
    };
    loop {
        match timekeeper().0.try_read() {
            None => continue,
            Some(tk) => {
                xtime = tk.xtime;
                drop(tk);
                nsecs = timekeeper().timekeeping_get_ns();
                // TODO 不同架构可能需要加上不同的偏移量
                break;
            }
        }
    }
    let sec = (xtime.tv_nsec as u64 + nsecs)
        .overflowing_rem(NSEC_PER_SEC.into())
        .0 as i64;
    // TODO 将xtime和当前时间源的时间相加
    xtime.tv_sec += sec;
    xtime.tv_nsec -= sec * NSEC_PER_SEC as i64;
    kdebug!(
        "xtime.tv_sec = {:?},xtime.tv_nsec = {:?}",
        xtime.tv_sec,
        xtime.tv_nsec
    );
    return xtime;
}

pub fn timekeeping_init() {
    timekeeper_init();
    kdebug!("timekeeper_init successfully");
    let mut rtc_time: RtcTime = RtcTime::default();
    rtc_time.get();

    // TODO 有ntp模块后 在此初始化ntp模块

    let clock = clocksource_default_clock();
    clock.enable();
    timekeeper().timekeeper_setup_internals(clock);
    // 暂时不支持其他架构平台对时间的设置 所以使用x86平台对应值初始化
    let timekeeper = &mut timekeeper().0.write();
    let irq_guard = unsafe { CurrentIrqArch::save_and_disable_irq() };
    // 初始化wall time到monotonic的时间
    let mut nsec = -timekeeper.xtime.tv_nsec;
    let mut sec = -timekeeper.xtime.tv_sec;
    //
    let num = nsec % NSEC_PER_SEC as i64;
    nsec += num * NSEC_PER_SEC as i64;
    sec -= num;
    timekeeper.wall_to_monotonic.tv_nsec = nsec;
    timekeeper.wall_to_monotonic.tv_sec = sec;
    drop(irq_guard);
}

// TODO xtime_updata
// TODO update_wall_time
/// 使用当前时钟源增加wall time
pub fn update_wall_time() {
    // 如果在休眠那就不更新
    if *TIMEKEEPING_SUSPENDED.read() {
        return;
    }
    let timekeeper = &mut timekeeper().0.write();
    let irq_guard = unsafe { CurrentIrqArch::save_and_disable_irq() };
    timekeeper.xtime_nsec = (timekeeper.xtime.tv_nsec as u64) << timekeeper.shift;
    // TODO 当有ntp模块之后 需要将timekeep与ntp进行同步并检查
    timekeeper.xtime.tv_nsec = ((timekeeper.xtime_nsec as i64) >> timekeeper.shift) + 1;
    timekeeper.xtime_nsec -= (timekeeper.xtime.tv_nsec as u64) << timekeeper.shift;

    if unlikely(timekeeper.xtime.tv_nsec >= NSEC_PER_SEC.into()) {
        timekeeper.xtime.tv_nsec -= NSEC_PER_SEC as i64;
        timekeeper.xtime.tv_sec += 1;
    }
    // TODO 需要检查是否更新时间源
    drop(irq_guard);
}
// TODO timekeeping_adjust
// TODO wall_to_monotic
