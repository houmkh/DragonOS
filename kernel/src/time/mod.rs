pub mod timekeep;
pub mod timer;
pub mod sleep;
/// 表示时间的结构体
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeSpec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}
