use core::ptr::null_mut;

use alloc::sync::Arc;

use crate::{
    exception::softirq2::{SoftirqNumber, SoftirqVec, SOFTIRQ_VECTORS},
    include::bindings::bindings::video_refresh_framebuffer,
};

pub struct VideoRefreshFramebuffer {}
impl SoftirqVec for VideoRefreshFramebuffer {
    fn run(&self) {
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

// ======= 以下为给C提供的接口,video重构完后请删除 =======
#[no_mangle]
pub extern "C" fn register_softirq_video() {
    let handler = Arc::new(VideoRefreshFramebuffer::new());
    SOFTIRQ_VECTORS
        .lock()
        .register_softirq(SoftirqNumber::VideoRefresh, handler)
        .expect("register_softirq_video run failed");
}
