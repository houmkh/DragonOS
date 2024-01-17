use core::intrinsics::{likely, unlikely};

use alloc::sync::Arc;
use system_error::SystemError;

use crate::{
    arch::{
        ipc::signal::{SigChildCode, Signal},
        sched::sched,
        CurrentIrqArch,
    },
    exception::InterruptArch,
    syscall::user_access::UserBufferWriter,
};

use super::{
    abi::WaitOption, pid::PidType, resource::RUsage, Pid, ProcessControlBlock, ProcessManager,
    ProcessState,
};

/// 内核wait4时的参数
#[derive(Debug)]
pub struct KernelWaitOption<'a> {
    pub pid_type: PidType,
    pub pid: Pid,
    pub options: WaitOption,
    pub ret_status: i32,
    pub ret_info: Option<WaitIdInfo>,
    pub ret_rusage: Option<&'a mut RUsage>,
    pub no_task_error: Option<SystemError>,
}

#[derive(Debug, Clone)]
pub struct WaitIdInfo {
    pub pid: Pid,
    pub status: i32,
    pub cause: i32,
}

impl<'a> KernelWaitOption<'a> {
    pub fn new(pid_type: PidType, pid: Pid, options: WaitOption) -> Self {
        Self {
            pid_type,
            pid,
            options,
            ret_status: 0,
            ret_info: None,
            ret_rusage: None,
            no_task_error: None,
        }
    }
}

pub fn kernel_wait4(
    mut pid: i64,
    wstatus_buf: Option<UserBufferWriter<'_>>,
    options: WaitOption,
    rusage_buf: Option<&mut RUsage>,
) -> Result<usize, SystemError> {
    // i64::MIN is not defined
    if pid == i64::MIN {
        return Err(SystemError::ESRCH);
    }

    // 判断pid类型
    let pidtype: PidType;

    if pid == -1 {
        pidtype = PidType::MAX;
    } else if pid < 0 {
        pidtype = PidType::PGID;
        kwarn!("kernel_wait4: currently not support pgid, default to wait for pid\n");
        pid = -pid;
    } else if pid == 0 {
        pidtype = PidType::PGID;
        kwarn!("kernel_wait4: currently not support pgid, default to wait for pid\n");
        pid = ProcessManager::current_pcb().pid().data() as i64;
    } else {
        pidtype = PidType::PID;
    }

    let pid = Pid(pid as usize);

    // 构造参数
    let mut kwo = KernelWaitOption::new(pidtype, pid, options);

    kwo.options.insert(WaitOption::WEXITED);
    kwo.ret_rusage = rusage_buf;

    // 调用do_wait，执行等待
    let r = do_wait(&mut kwo)?;

    // 如果有wstatus_buf，则将wstatus写入用户空间
    if let Some(mut wstatus_buf) = wstatus_buf {
        let wstatus = if let Some(ret_info) = &kwo.ret_info {
            ret_info.status
        } else {
            kwo.ret_status
        };
        wstatus_buf.copy_one_to_user(&wstatus, 0)?;
    }

    return Ok(r);
}

/// 参考 https://code.dragonos.org.cn/xref/linux-6.1.9/kernel/exit.c#1573
fn do_wait(kwo: &mut KernelWaitOption) -> Result<usize, SystemError> {
    let mut retval: Result<usize, SystemError>;
    // todo: 在signal struct里面增加等待队列，并在这里初始化子进程退出的回调，使得子进程退出时，能唤醒当前进程。
    macro_rules! no_task {
        () => {
            if let Some(err) = &kwo.no_task_error {
                retval = Err(err.clone());
            } else {
                retval = Ok(0);
            }

            if !kwo.options.contains(WaitOption::WNOHANG) {
                retval = Err(SystemError::ERESTARTSYS);
                if ProcessManager::current_pcb()
                    .sig_info()
                    .sig_pending()
                    .has_pending()
                    == false
                {
                    // todo: 增加子进程退出的回调后，这里可以直接等待在自身的child_wait等待队列上。
                    continue;
                } else {
                    break;
                }
            } else {
                break;
            }
        };
    }

    loop {
        kwo.no_task_error = Some(SystemError::ECHILD);
        let child_pcb = ProcessManager::find(kwo.pid).ok_or(SystemError::ECHILD);

        if kwo.pid_type != PidType::MAX && child_pcb.is_err() {
            no_task!();
        }

        if kwo.pid_type == PidType::PID {
            let child_pcb = child_pcb.unwrap();
            // 获取weak引用，以便于在do_waitpid中能正常drop pcb
            let child_weak = Arc::downgrade(&child_pcb);
            let r = do_waitpid(child_pcb, kwo);
            if r.is_some() {
                ProcessManager::current_pcb()
                    .sched_info()
                    .inner_lock_write_irqsave()
                    .set_state(ProcessState::Runnable);
                return r.unwrap();
            } else {
                child_weak.upgrade().unwrap().wait_queue.sleep();
            }
        } else if kwo.pid_type == PidType::MAX {
            // 等待任意子进程

            let current_pcb = ProcessManager::current_pcb();
            // todo: 对当前进程的每个线程来都执行以下代码
            {
                let r = do_wait_normal(kwo, &current_pcb);
                // if current_pcb.pid.data() == 5{

                //     kdebug!("wait normal: {r:?}");
                // }

                if r.is_ok() {
                    current_pcb
                        .sched_info()
                        .inner_lock_write_irqsave()
                        .set_state(ProcessState::Runnable);
                    return r;
                }

                let r = do_wait_ptrace(kwo, &current_pcb);

                if r.is_ok() {
                    current_pcb
                        .sched_info()
                        .inner_lock_write_irqsave()
                        .set_state(ProcessState::Runnable);
                    return r;
                }
            }
        } else {
            // todo: 对于pgid的处理
            kwarn!("kernel_wait4: currently not support {:?}", kwo.pid_type);
            ProcessManager::current_pcb()
                .sched_info()
                .inner_lock_write_irqsave()
                .set_state(ProcessState::Runnable);
            return Err(SystemError::EINVAL);
        }

        no_task!();
    }
    if ProcessManager::current_pcb().pid.data() == 5 {
        kdebug!("wait ptrace end: {retval:?}");
    }
    ProcessManager::current_pcb()
        .sched_info()
        .inner_lock_write_irqsave()
        .set_state(ProcessState::Runnable);
    kdebug!("12323234234234234");
    return retval;
}

#[inline(never)]
fn do_wait_normal(
    kwo: &mut KernelWaitOption,
    current_pcb: &Arc<ProcessControlBlock>,
) -> Result<usize, SystemError> {
    let rd_childen = current_pcb.children.read_irqsave();
    // todo: 这里有问题！如果正在for循环的过程中，子进程退出了，可能会导致父进程永远等待。
    for pid in rd_childen.iter() {
        // let pcb = ProcessManager::find(*pid).ok_or(SystemError::ECHILD)?;
        // let state = pcb.sched_info().inner_lock_read_irqsave().state();
        // if state.is_exited() {
        //     kwo.ret_status = state.exit_code().unwrap() as i32;
        //     drop(pcb);
        //     unsafe { ProcessManager::release(pid.clone()) };
        //     return Ok(pid.clone().into());
        // }

        let child_pcb = ProcessManager::find(*pid).ok_or(SystemError::ECHILD)?;

        let r = wait_consider_task(kwo, &child_pcb, false);
        if let Some(Ok(r)) = r {
            return Ok(r);
        }
    }
    drop(rd_childen);
    return Err(SystemError::ECHILD);
}

#[inline(never)]
fn do_wait_ptrace(
    kwo: &mut KernelWaitOption,
    current_pcb: &Arc<ProcessControlBlock>,
) -> Result<usize, SystemError> {
    let pt_childen = current_pcb.ptraced_childrens.lock_irqsave();
    kdebug!("wait ptrace: len: {}", pt_childen.len());
    // todo: 这里有问题！如果正在for循环的过程中，子进程退出了，可能会导致父进程永远等待。
    for child_pcb in pt_childen.iter() {
        kdebug!("wait ptrace: {:?}", child_pcb.pid());
        let r: Option<Result<usize, SystemError>> = wait_consider_task(kwo, &child_pcb, true);
        if let Some(Ok(r)) = r {
            return Ok(r);
        }

        kdebug!("wait ptrace: {:?}, err: {r:?}", child_pcb.pid());
    }
    drop(pt_childen);
    return Err(SystemError::ECHILD);
}

/// wait for task stopped and traced
///
/// 参考 https://code.dragonos.org.cn/xref/linux-6.1.9/kernel/exit.c#1247
#[inline(never)]
fn wait_task_stopped(
    kwo: &mut KernelWaitOption,
    is_ptrace: bool,
    child_pcb: &Arc<ProcessControlBlock>,
) -> Option<Result<usize, SystemError>> {
    // todo: 在stopped里面，添加code字段，表示停止的原因
    let exitcode = 0;

    if (!is_ptrace) && (!kwo.options.contains(WaitOption::WUNTRACED)) {
        kwo.ret_status = 0;
        return Some(Ok(0));
    }

    if likely(!(kwo.options.contains(WaitOption::WNOWAIT))) {
        kwo.ret_status = (exitcode << 8) | 0x7f;
    }

    // todo: 处理ptrace的exit code的问题

    if let Some(infop) = &mut kwo.ret_info {
        *infop = WaitIdInfo {
            pid: child_pcb.pid(),
            status: exitcode,
            cause: SigChildCode::Stopped.into(),
        };
    }

    return Some(Ok(child_pcb.pid().data()));
}

#[inline(never)]
fn wait_task_continued(
    kwo: &mut KernelWaitOption,
    child_pcb: &Arc<ProcessControlBlock>,
) -> Option<Result<usize, SystemError>> {
    if kwo.options.contains(WaitOption::WNOHANG) || kwo.options.contains(WaitOption::WNOWAIT) {
        if let Some(info) = &mut kwo.ret_info {
            *info = WaitIdInfo {
                pid: child_pcb.pid(),
                status: Signal::SIGCONT as i32,
                cause: SigChildCode::Continued.into(),
            };
        } else {
            kwo.ret_status = 0xffff;
        }

        return Some(Ok(0));
    }

    return None;
}

#[inline(never)]
fn wait_task_exited(
    kwo: &mut KernelWaitOption,
    child_pcb: &Arc<ProcessControlBlock>,
    state: ProcessState,
    is_ptrace: bool,
) -> Option<Result<usize, SystemError>> {
    let pid = child_pcb.pid();
    // kdebug!("wait4: child exited, pid: {:?}, status: {status}\n", pid);

    if likely(!kwo.options.contains(WaitOption::WEXITED)) {
        return None;
    }

    let status = state.exit_code().unwrap();

    // todo: 增加对线程组的group leader的处理

    if let Some(infop) = &mut kwo.ret_info {
        *infop = WaitIdInfo {
            pid,
            status: status as i32,
            cause: SigChildCode::Exited.into(),
        };
    }

    kwo.ret_status = status as i32;

    if likely(!is_ptrace)
        || kwo
            .options
            .contains(WaitOption::WCONTINUED | WaitOption::WEXITED)
    {
        kwo.no_task_error = None;
    }

    // kdebug!("wait4: to release {pid:?}");
    unsafe { ProcessManager::release(pid) };
    return Some(Ok(pid.into()));
}

/// Consider @child_pcb for a wait by parent.
#[inline(never)]
fn wait_consider_task(
    kwo: &mut KernelWaitOption,
    child_pcb: &Arc<ProcessControlBlock>,
    mut is_ptrace: bool,
) -> Option<Result<usize, SystemError>> {
    let state = child_pcb.sched_info().inner_lock_read_irqsave().state();

    if likely(!is_ptrace) && unlikely(!child_pcb.ptrace_flag.read_irqsave().is_empty()) {
        // 进程正在被trace

        // todo: 处理线程组相关逻辑： https://code.dragonos.org.cn/xref/linux-6.1.9/kernel/exit.c#1399

        is_ptrace = true;
    }

    kwo.no_task_error = None;
    // 获取退出码
    match state {
        ProcessState::Runnable => {
            return wait_task_continued(kwo, child_pcb);
        }
        ProcessState::Blocked(_) | ProcessState::Stopped => {
            return wait_task_stopped(kwo, is_ptrace, child_pcb);
        }
        ProcessState::Exited(_) => {
            return wait_task_exited(kwo, child_pcb, state, is_ptrace);
        }
    };
}

/// 等待子进程退出
///
/// 参考 https://code.dragonos.org.cn/xref/linux-6.1.9/kernel/exit.c#1547
fn do_waitpid(
    child_pcb: Arc<ProcessControlBlock>,
    kwo: &mut KernelWaitOption,
) -> Option<Result<usize, SystemError>> {
    let mut ptrace = false;
    // todo: 处理tgid

    if is_effectively_child(kwo, &child_pcb, ptrace) {
        if let Some(r) = wait_consider_task(kwo, &child_pcb, ptrace) {
            if r.is_ok() {
                return Some(r);
            }
        }
    }

    ptrace = true;

    if (!child_pcb.ptrace_flag.read_irqsave().is_empty())
        && is_effectively_child(kwo, &child_pcb, ptrace)
    {
        return wait_consider_task(kwo, &child_pcb, ptrace);
    }

    return None;
}

/// https://code.dragonos.org.cn/xref/linux-6.1.9/kernel/exit.c#1533
fn is_effectively_child(
    _kwo: &KernelWaitOption,
    child_pcb: &Arc<ProcessControlBlock>,
    is_ptrace: bool,
) -> bool {
    let parent = if is_ptrace {
        child_pcb.parent_pcb.read_irqsave().upgrade()
    } else {
        child_pcb.real_parent_pcb.read_irqsave().upgrade()
    };

    if parent.is_none() {
        return false;
    }
    let parent = parent.unwrap();

    if Arc::ptr_eq(&ProcessManager::current_pcb(), &parent) {
        return true;
    } else {
        // todo: 增加判断线程租
        return false;
    }
}
