use core::{
    hash::{Hash, Hasher},
    intrinsics::unlikely,
    mem::ManuallyDrop,
    sync::atomic::{compiler_fence, AtomicBool, AtomicI32, AtomicIsize, AtomicUsize, Ordering},
};

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::{Arc, Weak},
};
use hashbrown::HashMap;

use crate::{
    arch::{asm::current::current_pcb, cpu, process::ArchPCBInfo},
    filesystem::vfs::{file::FileDescriptorVec, FileType},
    include::bindings::bindings::CLONE_SIGNAL,
    kdebug,
    libs::{
        align::AlignedBox,
        casting::DowncastArc,
        rwlock::{RwLock, RwLockReadGuard, RwLockWriteGuard},
        spinlock::{SpinLock, SpinLockGuard},
    },
    mm::{
        percpu::PerCpuVar, set_INITIAL_PROCESS_ADDRESS_SPACE, ucontext::AddressSpace, VirtAddr,
        INITIAL_PROCESS_ADDRESS_SPACE,
    },
    net::socket::SocketInode,
    process::{
        fork::CloneFlags,
        init::initial_kernel_thread,
        kthread::{KernelThreadClosure, KernelThreadCreateInfo, KernelThreadMechanism},
    },
    sched::{
        core::{sched_enqueue, CPU_EXECUTING},
        SchedPolicy, SchedPriority,
    },
    smp::kick_cpu,
    syscall::SystemError,
};

use self::kthread::WorkerPrivate;

pub mod abi;
pub mod c_adapter;
pub mod exec;
pub mod fork;
pub mod idle;
pub mod init;
pub mod kthread;
pub mod pid;
pub mod process;
pub mod syscall;

/// 系统中所有进程的pcb
static ALL_PROCESS: SpinLock<Option<HashMap<Pid, Arc<ProcessControlBlock>>>> = SpinLock::new(None);

pub static mut SWITCH_RESULT: Option<PerCpuVar<SwitchResult>> = None;

#[derive(Debug)]
pub struct SwitchResult {
    pub prev_pcb: Option<Arc<ProcessControlBlock>>,
    pub next_pcb: Option<Arc<ProcessControlBlock>>,
}

impl SwitchResult {
    pub fn new() -> Self {
        Self {
            prev_pcb: None,
            next_pcb: None,
        }
    }
}

#[derive(Debug)]
pub struct ProcessManager;

impl ProcessManager {
    fn init() {
        static INIT_FLAG: AtomicBool = AtomicBool::new(false);
        if INIT_FLAG
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            panic!("ProcessManager has been initialized!");
        }

        unsafe {
            compiler_fence(Ordering::SeqCst);
            kdebug!("To create address space for INIT process.");
            // test_buddy();
            set_INITIAL_PROCESS_ADDRESS_SPACE(
                AddressSpace::new(true).expect("Failed to create address space for INIT process."),
            );
            kdebug!("INIT process address space created.");
            compiler_fence(Ordering::SeqCst);
        };

        ALL_PROCESS.lock().replace(HashMap::new());
        Self::arch_init();
        Self::init_idle();

        KernelThreadMechanism::init();

        // 初始化第一个内核线程
        {
            let create_info = KernelThreadCreateInfo::new(
                KernelThreadClosure::EmptyClosure((Box::new(initial_kernel_thread), ())),
                "init".to_string(),
            );
            KernelThreadMechanism::__inner_create(
                &create_info,
                CloneFlags::CLONE_VM | CloneFlags::CLONE_SIGNAL,
            )
            .unwrap_or_else(|e| panic!("Failed to create initial kernel thread, error: {:?}", e));
        }
    }

    /// 获取当前进程的pcb
    pub fn current_pcb() -> Arc<ProcessControlBlock> {
        return ProcessControlBlock::arch_current_pcb();
    }

    /// 根据pid获取进程的pcb
    ///
    /// ## 参数
    ///
    /// - `pid` : 进程的pid
    ///
    /// ## 返回值
    ///
    /// 如果找到了对应的进程，那么返回该进程的pcb，否则返回None
    pub fn find(pid: Pid) -> Option<Arc<ProcessControlBlock>> {
        return ALL_PROCESS.lock().as_ref()?.get(&pid).cloned();
    }

    /// 向系统中添加一个进程的pcb
    ///
    /// ## 参数
    ///
    /// - `pcb` : 进程的pcb
    ///
    /// ## 返回值
    ///
    /// 无
    pub fn add_pcb(pcb: Arc<ProcessControlBlock>) {
        ALL_PROCESS
            .lock()
            .as_mut()
            .unwrap()
            .insert(pcb.basic().pid(), pcb.clone());
    }

    /// 唤醒一个进程
    pub fn wakeup(pcb: &Arc<ProcessControlBlock>) -> Result<(), SystemError> {
        if pcb.sched_info().state() != ProcessState::Runnable {
            let mut writer = pcb.sched_info_mut();
            if writer.state() != ProcessState::Runnable {
                writer.set_state(ProcessState::Runnable);
                sched_enqueue(pcb.clone(), true);
                return Ok(());
            }
        }
        return Err(SystemError::EAGAIN_OR_EWOULDBLOCK);
    }

    /// 标志当前进程永久睡眠，移出调度队列
    pub fn sleep(interruptable: bool) -> Result<(), SystemError> {
        todo!()
    }

    /// 退出进程，回收资源
    ///
    /// 功能参考 https://opengrok.ringotek.cn/xref/DragonOS/kernel/src/process/process.c?r=40fe15e0953f989ccfeb74826d61621d43dea6bb&mo=7649&fi=246#246
    pub fn exit(exit_code: usize) -> ! {
        todo!()
    }

    pub unsafe fn release(pid: Pid) {
        ALL_PROCESS.lock().as_mut().unwrap().remove(&pid);
    }

    /// 上下文切换完成后的钩子函数
    unsafe fn switch_finish_hook() {
        let prev_pcb = SWITCH_RESULT
            .as_mut()
            .unwrap()
            .get_mut()
            .prev_pcb
            .take()
            .expect("prev_pcb is None");
        let next_pcb = SWITCH_RESULT
            .as_mut()
            .unwrap()
            .get_mut()
            .next_pcb
            .take()
            .expect("next_pcb is None");

        // 由于进程切换前使用了SpinLockGuard::leak()，所以这里需要手动释放锁
        prev_pcb.arch_info.force_unlock();
        next_pcb.arch_info.force_unlock();
    }

    /// 如果目标进程正在目标CPU上运行，那么就让这个cpu陷入内核态
    ///
    /// ## 参数
    ///
    /// - `pcb` : 进程的pcb
    pub fn kick(pcb: &Arc<ProcessControlBlock>) {
        ProcessManager::current_pcb().preempt_disable();
        let cpu_id = pcb.sched_info().on_cpu();

        if let Some(cpu_id) = cpu_id {
            let cpu_id = cpu_id as usize;

            if pcb.basic().pid() == CPU_EXECUTING[cpu_id].load(Ordering::SeqCst) {
                kick_cpu(cpu_id).expect("ProcessManager::kick(): Failed to kick cpu");
            }
        }

        ProcessManager::current_pcb().preempt_enable();
    }

    /// 创建进程时,将进程加入到其父进程的子进程链表中
    ///
    /// ## 参数
    ///
    /// - `pcb` : 当前进程
    pub fn add_child(pcb: &Arc<ProcessControlBlock>) {
        let childen = &pcb.parent_pcb.read().upgrade().clone().unwrap().children;
        childen.write().insert(pcb.basic().pid(), pcb.clone());
    }

    /// 子进程退出时,将子进程从父进程的子进程链表中移除
    ///
    /// ## 参数
    ///
    /// -‵pcb‵ : 要被移除的子进程
    pub fn rm_from_parent(pcb: &Arc<ProcessControlBlock>) {
        let childen = &pcb.parent_pcb.read().upgrade().clone().unwrap().children;
        childen.write().remove(&pcb.basic().pid());
    }

    /// 退出进程时,让初始进程收养所有子进程
    ///
    /// ## 参数
    ///
    /// -`pcb` : 要退出的进程
    pub fn adopte_childen(pcb: &Arc<ProcessControlBlock>) -> Result<(), SystemError> {
        let childen = &pcb.parent_pcb.read().upgrade().clone().unwrap().children;
        match ProcessManager::find(Pid(1)) {
            Some(init_pcb) => {
                let mut init_childen = init_pcb.children.write();
                for child in childen.read().iter() {
                    // 子进程的父进程改为1号进程
                    child
                        .1
                        .parent_pcb
                        .write()
                        .upgrade()
                        .replace(init_pcb.clone());
                    // 1号进程收养子进程
                    init_childen.insert(*child.0, child.1.clone());
                }
                childen.write().clear();
                Ok(())
            }
            // FIXME 没有找到1号进程返回什么错误码
            _ => Err(SystemError::ECHILD),
        }
    }
}

/// 上下文切换完成后的钩子函数
pub unsafe extern "C" fn switch_finish_hook() {
    ProcessManager::switch_finish_hook();
}

int_like!(Pid, AtomicPid, usize, AtomicUsize);

impl Hash for Pid {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Pid {
    pub fn to_string(&self) -> String {
        self.0.to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// The process is running on a CPU or in a run queue.
    Runnable,
    /// The process is waiting for an event to occur.
    /// 其中的bool表示该等待过程是否可以被打断。
    /// - 如果该bool为true,那么，硬件中断/信号/其他系统事件都可以打断该等待过程，使得该进程重新进入Runnable状态。
    /// - 如果该bool为false,那么，这个进程必须被显式的唤醒，才能重新进入Runnable状态。
    Blocked(bool),
    /// 进程被信号终止
    // Stopped(SignalNumber),
    /// 进程已经退出，usize表示进程的退出码
    Exited(usize),
}

bitflags! {
    /// pcb的标志位
    pub struct ProcessFlags: usize {
        /// 当前pcb表示一个内核线程
        const KTHREAD = 1 << 0;
        /// 当前进程需要被调度
        const NEED_SCHEDULE = 1 << 1;
        /// 进程由于vfork而与父进程存在资源共享
        const VFORK = 1 << 2;
        /// 进程不可被冻结
        const NOFREEZE = 1 << 3;
        /// 进程正在退出
        const EXITING = 1 << 4;
        /// 进程由于接收到终止信号唤醒
        const WAKEKILL = 1 << 5;
        /// 进程由于接收到信号而退出.(Killed by a signal)
        const SIGNALED = 1 << 6;
        /// 进程需要迁移到其他cpu上
        const NEED_MIGRATE = 1 << 7;
    }
}

#[derive(Debug)]
pub struct ProcessControlBlock {
    basic: RwLock<ProcessBasicInfo>,
    /// 当前进程的自旋锁持有计数
    preempt_count: AtomicUsize,

    flags: SpinLock<ProcessFlags>,
    worker_private: SpinLock<Option<WorkerPrivate>>,
    /// 进程的内核栈
    kernel_stack: RwLock<KernelStack>,

    /// 与调度相关的信息
    sched_info: RwLock<ProcessSchedulerInfo>,
    /// 与处理器架构相关的信息
    arch_info: SpinLock<ArchPCBInfo>,

    /// 父进程指针
    parent_pcb: RwLock<Weak<ProcessControlBlock>>,

    /// 子进程链表
    children: RwLock<HashMap<Pid, Arc<ProcessControlBlock>>>,
}

impl ProcessControlBlock {
    /// Generate a new pcb.
    ///
    /// ## 参数
    ///
    /// - `name` : 进程的名字
    /// - `kstack` : 进程的内核栈
    ///
    /// ## 返回值
    ///
    /// 返回一个新的pcb
    pub fn new(name: String, kstack: KernelStack) -> Arc<Self> {
        return Self::do_create_pcb(name, kstack, false);
    }

    /// 创建一个新的idle进程
    ///
    /// 请注意，这个函数只能在进程管理初始化的时候调用。
    pub fn new_idle(cpu_id: u32, kstack: KernelStack) -> Arc<Self> {
        let name = format!("idle-{}", cpu_id);
        return Self::do_create_pcb(name, kstack, true);
    }

    fn do_create_pcb(name: String, kstack: KernelStack, is_idle: bool) -> Arc<Self> {
        let pid = if is_idle {
            Pid(0)
        } else {
            Self::generate_pid()
        };
        let ppid = current_pcb().pid;
        let basic_info =
            ProcessBasicInfo::new(pid, Pid(0), Pid(ppid as usize), name, "/".to_string(), None);
        let preempt_count = AtomicUsize::new(0);
        let flags = SpinLock::new(ProcessFlags::empty());

        let sched_info = ProcessSchedulerInfo::new(None);
        let arch_info = SpinLock::new(ArchPCBInfo::new(Some(&kstack)));

        let ppcb = ProcessManager::find(Pid(ppid as usize)).unwrap();
        let pcb = Self {
            basic: basic_info,
            preempt_count,
            flags,
            kernel_stack: RwLock::new(kstack),
            worker_private: SpinLock::new(None),
            sched_info,
            arch_info,
            parent_pcb: RwLock::new(Arc::downgrade(&ppcb)),
            children: RwLock::new(HashMap::new()),
        };

        let pcb = Arc::new(pcb);

        unsafe { pcb.kernel_stack.write().set_pcb(Arc::clone(&pcb)).unwrap() };

        return pcb;
    }

    /// 生成一个新的pid
    fn generate_pid() -> Pid {
        static NEXT_PID: AtomicPid = AtomicPid::new(Pid(1));
        return NEXT_PID.fetch_add(Pid(1), Ordering::SeqCst);
    }

    /// 返回当前进程的锁持有计数
    pub fn preempt_count(&self) -> usize {
        return self.preempt_count.load(Ordering::SeqCst);
    }

    /// 增加当前进程的锁持有计数
    pub fn preempt_disable(&self) {
        self.preempt_count.fetch_add(1, Ordering::SeqCst);
    }

    /// 减少当前进程的锁持有计数
    pub fn preempt_enable(&self) {
        self.preempt_count.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn flags(&self) -> SpinLockGuard<ProcessFlags> {
        return self.flags.lock();
    }

    pub fn basic(&self) -> RwLockReadGuard<ProcessBasicInfo> {
        return self.basic.read();
    }

    pub fn set_name(&self, name: String) {
        self.basic.write().set_name(name);
    }

    pub fn basic_mut(&self) -> RwLockWriteGuard<ProcessBasicInfo> {
        return self.basic.write();
    }

    pub fn arch_info(&self) -> SpinLockGuard<ArchPCBInfo> {
        return self.arch_info.lock();
    }

    pub fn kernel_stack(&self) -> RwLockReadGuard<KernelStack> {
        return self.kernel_stack.read();
    }

    pub fn kernel_stack_mut(&self) -> RwLockWriteGuard<KernelStack> {
        return self.kernel_stack.write();
    }

    pub fn sched_info(&self) -> RwLockReadGuard<ProcessSchedulerInfo> {
        return self.sched_info.read();
    }

    pub fn sched_info_mut(&self) -> RwLockWriteGuard<ProcessSchedulerInfo> {
        return self.sched_info.write();
    }

    pub fn sched_info_mut_irqsave(&self) -> RwLockWriteGuard<ProcessSchedulerInfo> {
        return self.sched_info.write_irqsave();
    }

    pub fn worker_private(&self) -> SpinLockGuard<Option<WorkerPrivate>> {
        return self.worker_private.lock();
    }

    /// 获取文件描述符表的Arc指针
    #[inline(always)]
    pub fn fd_table(&self) -> Arc<RwLock<FileDescriptorVec>> {
        return self.basic.read().fd_table().unwrap();
    }

    /// 根据文件描述符序号，获取socket对象的Arc指针
    ///
    /// ## 参数
    ///
    /// - `fd` 文件描述符序号
    ///
    /// ## 返回值
    ///
    /// Option(&mut Box<dyn Socket>) socket对象的可变引用. 如果文件描述符不是socket，那么返回None
    pub fn get_socket(&self, fd: i32) -> Option<Arc<SocketInode>> {
        let binding = ProcessManager::current_pcb().fd_table();
        let fd_table_guard = binding.read();

        let f = fd_table_guard.get_file_ref_by_fd(fd)?;

        if f.file_type() != FileType::Socket {
            return None;
        }
        let socket: Arc<SocketInode> = f
            .inode()
            .downcast_arc::<SocketInode>()
            .expect("Not a socket inode");
        return Some(socket);
    }
}

/// 进程的基本信息
///
/// 这个结构体保存进程的基本信息，主要是那些不会随着进程的运行而经常改变的信息。
#[derive(Debug)]
pub struct ProcessBasicInfo {
    /// 当前进程的pid
    pid: Pid,
    /// 当前进程的进程组id
    pgid: Pid,
    /// 当前进程的父进程的pid
    ppid: Pid,
    /// 进程的名字
    name: String,

    /// 当前进程的工作目录
    cwd: String,

    /// 用户地址空间
    user_vm: Option<Arc<AddressSpace>>,

    /// 文件描述符表
    fd_table: Option<Arc<RwLock<FileDescriptorVec>>>,
}

impl ProcessBasicInfo {
    pub fn new(
        pid: Pid,
        pgid: Pid,
        ppid: Pid,
        name: String,
        cwd: String,
        user_vm: Option<Arc<AddressSpace>>,
    ) -> RwLock<Self> {
        let fd_table = Arc::new(RwLock::new(FileDescriptorVec::new()));
        return RwLock::new(Self {
            pid,
            pgid,
            ppid,
            name,
            cwd,
            user_vm,
            fd_table: Some(fd_table),
        });
    }

    pub fn pid(&self) -> Pid {
        return self.pid;
    }

    pub fn pgid(&self) -> Pid {
        return self.pgid;
    }

    pub fn ppid(&self) -> Pid {
        return self.ppid;
    }

    pub fn name(&self) -> &str {
        return &self.name;
    }

    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    pub fn path(&self) -> String {
        return self.cwd.clone();
    }
    pub fn set_path(&mut self, path: String) {
        return self.cwd = path;
    }

    pub fn user_vm(&self) -> Option<Arc<AddressSpace>> {
        return self.user_vm.clone();
    }

    pub unsafe fn set_user_vm(&mut self, user_vm: Option<Arc<AddressSpace>>) {
        self.user_vm = user_vm;
    }

    pub fn fd_table(&self) -> Option<Arc<RwLock<FileDescriptorVec>>> {
        return self.fd_table.clone();
    }

    pub fn set_fd_table(&mut self, fd_table: Option<Arc<RwLock<FileDescriptorVec>>>) {
        self.fd_table = fd_table;
    }
}

#[derive(Debug)]
pub struct ProcessSchedulerInfo {
    /// 当前进程所在的cpu
    on_cpu: AtomicI32,
    /// 如果当前进程等待被迁移到另一个cpu核心上（也就是flags中的PF_NEED_MIGRATE被置位），
    /// 该字段存储要被迁移到的目标处理器核心号
    migrate_to: AtomicI32,

    /// 当前进程的状态
    state: ProcessState,
    /// 进程的调度策略
    sched_policy: SchedPolicy,
    /// 进程的调度优先级
    priority: SchedPriority,
    /// 当前进程的虚拟运行时间
    virtual_runtime: AtomicIsize,
    /// 由实时调度器管理的时间片
    rt_time_slice: AtomicIsize,
}

impl ProcessSchedulerInfo {
    pub fn new(on_cpu: Option<u32>) -> RwLock<Self> {
        let cpu_id = match on_cpu {
            Some(cpu_id) => cpu_id as i32,
            None => -1,
        };
        return RwLock::new(Self {
            on_cpu: AtomicI32::new(cpu_id),
            migrate_to: AtomicI32::new(-1),
            state: ProcessState::Blocked(false),
            sched_policy: SchedPolicy::CFS,
            virtual_runtime: AtomicIsize::new(0),
            rt_time_slice: AtomicIsize::new(0),
            priority: SchedPriority::new(100).unwrap(),
        });
    }

    pub fn on_cpu(&self) -> Option<u32> {
        let on_cpu = self.on_cpu.load(Ordering::SeqCst);
        if on_cpu == -1 {
            return None;
        } else {
            return Some(on_cpu as u32);
        }
    }

    pub fn set_on_cpu(&self, on_cpu: Option<u32>) {
        if let Some(cpu_id) = on_cpu {
            self.on_cpu.store(cpu_id as i32, Ordering::SeqCst);
        } else {
            self.on_cpu.store(-1, Ordering::SeqCst);
        }
    }

    pub fn migrate_to(&self) -> Option<u32> {
        let migrate_to = self.migrate_to.load(Ordering::SeqCst);
        if migrate_to == -1 {
            return None;
        } else {
            return Some(migrate_to as u32);
        }
    }

    pub fn set_migrate_to(&self, migrate_to: Option<u32>) {
        if let Some(data) = migrate_to {
            self.migrate_to.store(data as i32, Ordering::SeqCst);
        } else {
            self.migrate_to.store(-1, Ordering::SeqCst)
        }
    }

    pub fn state(&self) -> ProcessState {
        return self.state;
    }

    fn set_state(&mut self, state: ProcessState) {
        self.state = state;
    }

    pub fn policy(&self) -> SchedPolicy {
        return self.sched_policy;
    }

    pub fn virtual_runtime(&self) -> isize {
        return self.virtual_runtime.load(Ordering::SeqCst);
    }

    pub fn set_virtual_runtime(&self, virtual_runtime: isize) {
        self.virtual_runtime
            .store(virtual_runtime, Ordering::SeqCst);
    }
    pub fn increase_virtual_runtime(&self, delta: isize) {
        self.virtual_runtime.fetch_add(delta, Ordering::SeqCst);
    }

    pub fn rt_time_slice(&self) -> isize {
        return self.rt_time_slice.load(Ordering::SeqCst);
    }

    pub fn set_rt_time_slice(&self, rt_time_slice: isize) {
        self.rt_time_slice.store(rt_time_slice, Ordering::SeqCst);
    }

    pub fn increase_rt_time_slice(&self, delta: isize) {
        self.rt_time_slice.fetch_add(delta, Ordering::SeqCst);
    }

    pub fn priority(&self) -> SchedPriority {
        return self.priority;
    }
}

#[derive(Debug)]
pub struct KernelStack {
    stack: Option<AlignedBox<[u8; KernelStack::SIZE], { KernelStack::ALIGN }>>,
    /// 标记该内核栈是否可以被释放
    can_be_freed: bool,
}

impl KernelStack {
    pub const SIZE: usize = 0x4000;
    pub const ALIGN: usize = 0x4000;

    pub fn new() -> Result<Self, SystemError> {
        return Ok(Self {
            stack: Some(
                AlignedBox::<[u8; KernelStack::SIZE], { KernelStack::ALIGN }>::new_zeroed()?,
            ),
            can_be_freed: true,
        });
    }

    /// 根据已有的空间，构造一个内核栈结构体
    ///
    /// 仅仅用于BSP启动时，为idle进程构造内核栈。其他时候使用这个函数，很可能造成错误！
    pub unsafe fn from_existed(base: VirtAddr) -> Result<Self, SystemError> {
        if base.is_null() || base.check_aligned(Self::ALIGN) == false {
            return Err(SystemError::EFAULT);
        }

        return Ok(Self {
            stack: Some(
                AlignedBox::<[u8; KernelStack::SIZE], { KernelStack::ALIGN }>::new_unchecked(
                    base.data() as *mut [u8; KernelStack::SIZE],
                ),
            ),
            can_be_freed: false,
        });
    }

    /// 返回内核栈的起始虚拟地址(低地址)
    pub fn start_address(&self) -> VirtAddr {
        return VirtAddr::new(self.stack.as_ref().unwrap().as_ptr() as usize);
    }

    /// 返回内核栈的结束虚拟地址(高地址)(不包含该地址)
    pub fn stack_max_address(&self) -> VirtAddr {
        return VirtAddr::new(self.stack.as_ref().unwrap().as_ptr() as usize + Self::SIZE);
    }

    pub unsafe fn set_pcb(&mut self, pcb: Arc<ProcessControlBlock>) -> Result<(), SystemError> {
        // 将一个Arc<ProcessControlBlock>放到内核栈的最低地址处
        let p: *const ProcessControlBlock = Arc::into_raw(pcb);
        // 如果内核栈的最低地址处已经有了一个pcb，那么，这里就不再设置,直接返回错误
        if unlikely(!p.is_null()) {
            return Err(SystemError::EPERM);
        }
        // 将pcb的地址放到内核栈的最低地址处
        unsafe {
            *(self.stack.as_ref().unwrap().as_ptr() as *mut *const ProcessControlBlock) = p;
        }

        return Ok(());
    }

    /// 返回指向当前内核栈pcb的Arc指针
    pub unsafe fn pcb(&self) -> Option<Arc<ProcessControlBlock>> {
        // 从内核栈的最低地址处取出pcb的地址
        let p = self.stack.as_ref().unwrap().as_ptr() as *const ProcessControlBlock;
        if unlikely(p.is_null()) {
            return None;
        }

        // 为了防止内核栈的pcb指针被释放，这里需要将其包装一下，使得Arc的drop不会被调用
        let arc_wrapper: ManuallyDrop<Arc<ProcessControlBlock>> =
            ManuallyDrop::new(Arc::from_raw(p));

        let new_arc: Arc<ProcessControlBlock> = Arc::clone(&arc_wrapper);
        return Some(new_arc);
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        let pcb_ptr: Arc<ProcessControlBlock> = unsafe {
            Arc::from_raw(self.stack.as_ref().unwrap().as_ptr() as *const ProcessControlBlock)
        };
        drop(pcb_ptr);
        // 如果该内核栈不可以被释放，那么，这里就forget，不调用AlignedBox的drop函数
        if !self.can_be_freed {
            let bx = self.stack.take();
            core::mem::forget(bx);
        }
    }
}

pub fn process_init() {
    ProcessManager::init();
}
