use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use num_traits::FromPrimitive;
use smoltcp::wire::IpProtocol;
use x86::current::syscall;

use crate::{
    arch::{interrupt::TrapFrame, ipc::signal::Signal, CurrentIrqArch},
    exception::InterruptArch,
    mm::{verify_area, VirtAddr},
    process::ProcessControlBlock,
    syscall::Syscall,
};
use system_error::SystemError;

use super::{Pid, ProcessFlags, ProcessManager};
#[derive(PartialEq)]
enum PtEventMsg {
    EmsgSysExit,
    EmsgSysEntry,
}

/// ptrace系统调用的请求类型
///
/// 对应linux的 `PTRACE_*`
///
/// 参考 https://code.dragonos.org.cn/xref/linux-6.1.9/include/uapi/linux/ptrace.h#11
#[derive(PartialEq, FromPrimitive)]
#[repr(usize)]
#[allow(dead_code)]
pub enum PtraceRequest {
    TraceMe = 0,
    PeekText = 1,
    PeekData = 2,
    PeekUser = 3,
    PokeText = 4,
    PokeData = 5,
    PokeUser = 6,
    Cont = 7,
    Kill = 8,
    SingleStep = 9,
    Attach = 16,
    Detach = 17,
    Syscall = 24,
    // 其他架构无关的添加操作定义在0x4200-0x4300之间。
    SetOptions = 0x4200,
    GetEventMsg = 0x4201,
    GetSigInfo = 0x4202,
    SetSigInfo = 0x4203,
    GetRegSet = 0x4204,
    SetRegSet = 0x4205,
    Seize = 0x4206,
    Interrupt = 0x4207,
    Listen = 0x4208,
    PeekSigInfo = 0x4209, // 将PeekSigInfo作为单独的值列出，以便在其他代码中识别和引用。
}

impl TryFrom<usize> for PtraceRequest {
    type Error = SystemError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        <Self as FromPrimitive>::from_usize(value).ok_or(SystemError::EINVAL)
    }
}

pub enum PtEvent {
    PtraceEventFork,
    PtraceEventVfork,
    PtraceEventClone,
    PtraceEventExec,
    PtraceEventVforkDone,
    PtraceEventExit,
    PtraceEventSeccomp,
}
bitflags! {
    pub struct PtraceFlag: u32 {
        const NOT_PTRACED = 0x0;
        const PT_PTRACED = 0x00000001;
        const PT_DTRACE	= 0x00000002;
        const PT_TRACESYSGOOD =	0x00000004;
        const PT_PTRACE_CAP	= 0x00000008;
        const PT_TRACE_FORK = 0x00000010;
        const PT_TRACE_VFORK = 0x00000020;
        const PT_TRACE_CLONE = 0x00000040;
        const PT_TRACE_EXEC = 0x00000080;
        const PT_TRACE_VFORK_DONE =	0x00000100;
        const PT_TRACE_EXIT = 0x00000200;
        const PT_SEIZE = 0x00000400;
        const PT_TRACE_MASK = 0x000003f4;
  }
}

/// 被ptrace的子进程
#[derive(Debug)]
pub struct PtracedChildrens {
    data: Vec<Arc<ProcessControlBlock>>,
}

impl PtracedChildrens {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// 添加子进程
    ///
    /// ## 参数
    ///
    /// - child: 子进程
    ///
    /// ## 说明
    ///
    /// 如果已经存在，则不添加
    ///
    pub fn add(&mut self, child: Arc<ProcessControlBlock>) {
        // 去重
        if self.data.iter().find(|x| Arc::ptr_eq(x, &child)).is_none() {
            kdebug!("PPPPUSH!!!!!");
            self.data.push(child);
        }
    }

    /// 移除子进程
    ///
    /// ## 参数
    ///
    /// - pid: 子进程的pid
    ///
    /// ## 返回值
    ///
    /// - Some: 返回被移除的子进程
    /// - None: 没有找到对应的子进程
    pub fn remove(&mut self, pid: Pid) -> Option<Arc<ProcessControlBlock>> {
        let index = self.data.iter().position(|x| x.pid() == pid);
        if index.is_some() {
            let remove = self.data.remove(index.unwrap());
            return Some(remove);
        }
        return None;
    }

    pub fn iter(&self) -> PtracedChildrensIter<'_> {
        return PtracedChildrensIter {
            ptraced_childrens: self,
            index: 0,
        };
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

pub struct PtracedChildrensIter<'a> {
    ptraced_childrens: &'a PtracedChildrens,
    index: usize,
}

impl<'a> Iterator for PtracedChildrensIter<'a> {
    type Item = &'a Arc<ProcessControlBlock>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index < self.ptraced_childrens.data.len() {
            let ret = &self.ptraced_childrens.data[self.index];
            self.index += 1;

            return Some(ret);
        }

        return None;
    }
}

/// 让child成为parent的子进程
///
fn ptrace_link(child: Arc<ProcessControlBlock>, parent: Arc<ProcessControlBlock>) {
    // kdebug!("enter ptrace_link");
    let ppid: Pid = parent.pid();
    // kdebug!("parent = {:?}, child = {:?}", ppid, pid);
    child.basic_mut().set_ppid(ppid);
    let mut new_parent = child.cur_parent_pcb.write();
    (*new_parent) = Arc::downgrade(&parent);
    drop(new_parent);
    parent.ptraced_childrens.lock_irqsave().add(child);
    kdebug!("exit ptrace_link");
}

fn ptrace_traceme() {
    kdebug!("enter ptrace_traceme");

    // TODO 错误处理
    // 判断当前进程是否已经在被跟踪
    let cur_pcb = ProcessManager::current_pcb();
    let pid = cur_pcb.pid();
    // kdebug!("i'm {:?}", pid);
    let mut ptrace = cur_pcb.ptrace_flag.write();
    if !ptrace.contains(PtraceFlag::PT_PTRACED) {
        // kdebug!("i'm not be traced");
        let cur_pcb = ProcessManager::current_pcb();
        let temp_pcb = cur_pcb.clone();
        let parent = temp_pcb.parent_pcb.read();
        let p_pcb = (*parent).clone().upgrade();
        drop(parent);
        // TODO 要判断父结点是否已经调用exit_ptrace
        if p_pcb.is_some() {
            // kdebug!("link parent and child");
            let pcb: Arc<ProcessControlBlock> = p_pcb.unwrap();
            let status = pcb.sched_info().inner_lock_read_irqsave().state();
            if status.is_exited() {
                kdebug!("parent is exited");
                return;
            }
            // 将当前进程标记为被追踪状态
            (*ptrace).insert(PtraceFlag::PT_PTRACED);
            // 将当前进程成为ptracer的子进程
            drop(ptrace);
            ptrace_link(cur_pcb, pcb);
        }
    }
    // kdebug!("exit ptrace_traceme");

    let guard = unsafe { CurrentIrqArch::save_and_disable_irq() };
    ProcessManager::mark_sleep(true).unwrap_or_else(|e| {
        kerror!(
            "ptrace traceme sleep error :{:?},failed to sleep process :{:?}",
            e,
            ProcessManager::current_pcb(),
        );
    });
    drop(guard);
    Syscall::kill(ProcessManager::current_pcb().pid(), Signal::SIGCHLD as i32).ok();
    // kdebug!("send sigchld to myself");
}
/// 将指定的进程附加在当前进程上
fn ptrace_attach(request: PtraceRequest, pid: Pid) -> Result<(), SystemError> {
    kdebug!("enter ptrace_attach");

    // 判断当前进程与被跟踪进程是否相同
    if pid == ProcessManager::current_pcb().pid() {
        return Err(SystemError::EPERM);
    }
    let op_pcb: Option<Arc<ProcessControlBlock>> = ProcessManager::find(pid);
    if op_pcb.is_none() {
        return Err(SystemError::ESRCH);
    }
    let pcb: Arc<ProcessControlBlock> = op_pcb.unwrap();
    // 判断要跟踪的进程是否已退出或已被跟踪
    if pcb.flags().contains(ProcessFlags::EXITING)
        || pcb.ptrace_flag.read().contains(PtraceFlag::PT_PTRACED)
    {
        return Err(SystemError::EPERM);
    }
    let mut seize = false;
    // 判断是否为seize模式
    if request == PtraceRequest::Seize {
        seize = true;
    }
    if seize {
        let mut flag = pcb.ptrace_flag.write();
        (*flag).insert(PtraceFlag::PT_PTRACED | PtraceFlag::PT_SEIZE);
    } else {
        let mut flag = pcb.ptrace_flag.write();
        (*flag).insert(PtraceFlag::PT_PTRACED);
    }
    // TODO 处理seize的情况,即不会停下调试的情况
    // 将pcb连接到当前进程，当前进程就是tracer
    ptrace_link(pcb.clone(), ProcessManager::current_pcb());
    // 给pcb发送sigstop信号，暂停pcb
    if let Err(e) = Syscall::kill(pid, Signal::SIGSTOP as i32) {
        return Err(e);
    }

    // 将task子进程设置为停止状态

    kdebug!("exit ptrace_attach");
    Ok(())
}
/// 揭开ptracer和ptracee之间的关系
fn ptrace_detach(pid: Pid) -> Result<(), SystemError> {
    let op = ProcessManager::find(pid);
    if op.is_none() {
        return Err(SystemError::ESRCH);
    }
    let pcb = op.unwrap();
    ptrace_unlink(pcb.clone());
    Ok(())
}

fn ptrace_unlink(pcb: Arc<ProcessControlBlock>) {
    let real_parent = pcb.parent_pcb.read().clone();
    let mut cur_parent = pcb.cur_parent_pcb.write();
    // 从父进程的ptrace数组里面删除当前pcb
    cur_parent
        .upgrade()
        .map(|p| p.ptraced_childrens.lock_irqsave().remove(pcb.pid()));

    // 将当前的父进程改成真正的父进程
    *cur_parent = real_parent;
    let real_ppid = pcb.basic().pgid();
    pcb.basic_mut().set_ppid(real_ppid);
    // 清理标志位
    let mut ptraced = pcb.ptrace_flag.write();
    ptraced.bits = 0;
}
/// 读取寄存器中的信息并写回用户态
fn ptrace_readdate(pid: Pid, user_frame: *mut TrapFrame) -> Result<(), SystemError> {
    let pcb = ProcessManager::find(pid).unwrap();
    let op_frame = unsafe { pcb.arch_info().get_trapframe() };
    let frame: TrapFrame;
    match op_frame {
        Some(_) => frame = op_frame.unwrap(),
        None => return Err(SystemError::EINVAL),
    }
    unsafe {
        (*user_frame).cs = frame.cs;
        (*user_frame).ds = frame.ds;
        (*user_frame).es = frame.es;
        (*user_frame).errcode = frame.errcode;
        (*user_frame).func = frame.func;
        (*user_frame).r10 = frame.r10;
        (*user_frame).r11 = frame.r11;
        (*user_frame).r12 = frame.r12;
        (*user_frame).r13 = frame.r13;
        (*user_frame).r14 = frame.r14;
        (*user_frame).r15 = frame.r15;
        (*user_frame).r8 = frame.r8;
        (*user_frame).r9 = frame.r9;
        (*user_frame).rsp = frame.rsp;
        (*user_frame).ss = frame.ss;
        (*user_frame).rax = frame.rax;
        (*user_frame).rbx = frame.rbx;
        (*user_frame).rbp = frame.rbp;
        (*user_frame).rcx = frame.rcx;
        (*user_frame).rdi = frame.rdi;
        (*user_frame).rdx = frame.rdx;
        (*user_frame).rflags = frame.rflags;
        (*user_frame).rip = frame.rip;
        (*user_frame).rsi = frame.rsi;
        (*user_frame).rsp = frame.rsp;
    }
    Ok(())
}
#[allow(dead_code)]
fn ptrace_writedate() {}

#[allow(dead_code)]
fn ptrace_get_syscall_info_entry() {}

#[allow(dead_code)]
fn ptrace_get_syscall_info_exit() {}
/// 在进入和退出系统调用的时候获取系统调用信息
fn ptrace_get_syscall_info(eventmsg: PtEventMsg) {
    match eventmsg {
        PtEventMsg::EmsgSysExit => ptrace_get_syscall_info_exit(),
        PtEventMsg::EmsgSysEntry => ptrace_get_syscall_info_entry(),
    }
}

/// 在进入和退出系统调用时报告父进程
fn ptrace_report_syscall() {
    // 检查是否处于被追踪状态
    let cur_pcb = ProcessManager::current_pcb();
    if cur_pcb.ptraced_get_status(PtraceFlag::PT_PTRACED) {
        Syscall::kill(cur_pcb.basic().ppid(), Signal::SIGTRAP as i32);
    }
    // 检查是否发送sigtrap信号

    // 发送sigtrap

    // 将信息写入用户态
}

/// 分流不同的request
pub fn do_ptrace(
    request: PtraceRequest,
    proc: usize,
    addr: u64,
    data: u64,
) -> Result<usize, SystemError> {
    let pid = Pid(proc);
    if pid == Pid(1) {
        return Err(SystemError::EPERM);
    }
    match request {
        PtraceRequest::TraceMe => {
            ptrace_traceme();
            return Ok(0);
        }
        PtraceRequest::Seize => todo!(),
        PtraceRequest::Interrupt => todo!(),
        PtraceRequest::Kill => todo!(),
        PtraceRequest::Detach => {
            // TODO ptrace_detach
            if let Err(e) = ptrace_detach(pid) {
                return Err(e);
            }
            return Ok(0);
        }
        PtraceRequest::Attach => {
            if let Err(e) = ptrace_attach(request, pid) {
                return Err(e);
            }
            return Ok(0);
        }
        _ => {
            // TODO 根据不同的硬件架构处理剩余的ptrace请求
            if let Err(e) = ptrace_request(request, pid, addr, data) {
                return Err(e);
            }
            Ok(0)
        }
    }
    // TODO arch_ptrace未返回错误或者请求不等于detach调用unfreeze
}

/// 对不同的request进行分流
fn ptrace_request(
    request: PtraceRequest,
    pid: Pid,
    addr: u64,
    data: u64,
) -> Result<(), SystemError> {
    match request {
        PtraceRequest::PeekData | PtraceRequest::PeekText => {
            // TODO generic_ptrace_peekdata
            Ok(())
        }
        PtraceRequest::PokeData | PtraceRequest::PokeText => {
            // TODO generic_ptrace_pokedata
            Ok(())
        }
        PtraceRequest::Interrupt => todo!(),
        // PtraceRequest::PtraceOldsetoptions => todo!(),
        PtraceRequest::SetOptions => todo!(),
        PtraceRequest::GetEventMsg => todo!(),
        PtraceRequest::PeekSigInfo => todo!(),
        PtraceRequest::GetSigInfo => todo!(),
        PtraceRequest::SetSigInfo => todo!(),
        PtraceRequest::Listen => todo!(),
        // PtraceRequest::PtraceGetfdpic => todo!(),

        PtraceRequest::Syscall
        | PtraceRequest::SingleStep
        // | PtraceRequest::PtraceSingleblock
        // | PtraceRequest::PtraceSysemu
        // | PtraceRequest::PtraceSysemuSinglestep
        | PtraceRequest::Cont => ptrace_resume(request, pid),

        PtraceRequest::GetRegSet => {
            let user_data = data as *mut TrapFrame;
            let vaddr = VirtAddr::new(user_data as usize);
            match verify_area(vaddr, core::mem::size_of::<TrapFrame>()) {
                // Ok(_) => ptrace_readdate(frame, user_data),
                Ok(_) => ptrace_readdate(pid, user_data),
                Err(_) => todo!(),
            }
        }
        PtraceRequest::SetRegSet => todo!(),
        PtraceRequest::GetSigInfo => todo!(),
        // PtraceRequest::PtraceSeccompGetFilter => todo!(),
        // PtraceRequest::PtraceSeccompGetMetadata => todo!(),
        // PtraceRequest::PtraceGetRseqConfiguration => todo!(),
        _ => Ok(()),
    }
}
// 根据不同的request设置进程的标志位
fn ptrace_resume(_request: PtraceRequest, pid: Pid) -> Result<(), SystemError> {
    // 唤醒子进程执行系统调用
    // TODO match request
    // 暂时只考虑syscall的情况
    let pcb = ProcessManager::find(pid);
    match pcb {
        Some(p) => {
            return ProcessManager::wakeup_stop(&p);
        }
        None => Err(SystemError::ESRCH),
    }
}
/// 给自身发送sigtap信号，并记录trapframe
pub fn ptrace_stop(frame: &TrapFrame) {
    Syscall::kill(ProcessManager::current_pcb().pid(), Signal::SIGTRAP as i32);
    // TODO arch info记录frame信息
    let pcb = ProcessManager::current_pcb();
    let arch_info = &mut pcb.arch_info.lock();
    arch_info.store_trapframe(frame)
}
