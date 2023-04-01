use core::ptr::null_mut;

use alloc::sync::Arc;

use crate::{
    exception::softirq::{softirq_vectors, SoftirqNumber, SoftirqVec},
    include::bindings::bindings::video_refresh_framebuffer,
    kdebug,
};

#[derive(Debug)]
pub struct VideoRefreshFramebuffer;
impl SoftirqVec for VideoRefreshFramebuffer {
    fn run(&self) {
        kdebug!("VideoRefreshFramebuffer run");
        unsafe {
            video_refresh_framebuffer(null_mut());
        }
    }
}
impl VideoRefreshFramebuffer {
    pub fn new() -> VideoRefreshFramebuffer {
        VideoRefreshFramebuffer {}
    }
}

pub fn register_softirq_video() {
    kdebug!("register_softirq_video");
    let handler = Arc::new(VideoRefreshFramebuffer::new());
    softirq_vectors()
        .register_softirq(SoftirqNumber::VideoRefresh, handler)
        .expect("register_softirq_video run failed");
}
// ======= 以下为给C提供的接口,video重构完后请删除 =======
#[no_mangle]
pub extern "C" fn rs_register_softirq_video() {
    register_softirq_video();
}
