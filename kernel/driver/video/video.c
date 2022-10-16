#include "video.h"
#include <common/kprint.h>
#include <common/kthread.h>
#include <common/printk.h>
#include <common/spinlock.h>
#include <common/time.h>
#include <driver/multiboot2/multiboot2.h>
#include <driver/uart/uart.h>
#include <exception/softirq.h>
#include <mm/mm.h>
#include <mm/slab.h>
#include <process/process.h>
#include <sched/sched.h>
#include <time/timer.h>
uint64_t video_refresh_expire_jiffies = 0;
uint64_t video_last_refresh_pid = -1;

struct scm_buffer_info_t video_frame_buffer_info = {0};
static struct multiboot_tag_framebuffer_info_t __fb_info;
static struct scm_buffer_info_t *video_refresh_target = NULL;
static struct process_control_block *video_daemon_pcb = NULL;
static spinlock_t daemon_refresh_lock;

struct vbe_info_block
{

    uint8_t vbe_signature[5];      // VBE识别标志
    uint16_t vbe_version;          // VBE版本
    uint32_t oem_string_ptr;       // OEM字符串指针
    uint8_t capabilities;          //图形控制器的机能
    uint32_t video_mode_ptr;       // VedioModeList指针
    uint16_t total_memory;         // 64KB内存块数量
    uint16_t oem_soft_ware_rev;    // VBE软件版本
    uint32_t oem_verdor_name_ptr;  // OEM供应商名字指针
    uint32_t oem_product_name_ptr; // OEM产品名指针
    uint32_t oem_product_rev_otr;  // OEM产品版本指针
    uint8_t reserved[222];         //保留
    uint8_t oem_data[256];         // OEM数据
};

struct mode_info_block
{
    //所有VBE版本强制提供的信息
    uint16_t mode_atrributes;     //模式属性
    uint8_t win_a_attributes;     //窗口A属性
    uint8_t win_b_attributes;     //窗口B属性
    uint16_t win_granularity;     //窗口颗粒度
    uint16_t win_size;            //窗口大小
    uint16_t win_a_sigment;       //窗口A的段地址
    uint16_t win_b_sigment;       //窗口B的段地址
    uint32_t win_func_ptr;        //窗口功能的人口地址（实模式）
    uint16_t bytes_per_scan_line; //每条扫描线占用字节数

    // VBE 1.2以上版本强制提供的信息
    uint16_t x_resolution;         //水平分辨率（像素或字符）
    uint16_t y_resolution;         //垂直分辨率（像素或字符）
    uint8_t x_char_size;           //字符宽度（像索）
    uint8_t y_char_size;           //字符高度
    uint8_t number_of_planes;      //内存平面数盘
    uint8_t bits_per_pixel;        //每像素占用位宽
    uint8_t number_of_backs;       //块数量
    uint8_t memory_model;          //内存模式类型
    uint8_t bank_size;             //块容量
    uint8_t number_of_image_pages; //图像页数量
    uint8_t reserved;              //为分页功能保留使用

    //直接颜色描画区域
    uint8_t red_mask_size;          // Direct Color的红色屏蔽位宽
    uint8_t red_field_position;     //红色屏蔽位的起始位置
    uint8_t green_mask_size;        // Direct Color的绿色屏蔽位宽
    uint8_t green_field_position;   //绿色屏蔽位的起始位置
    uint8_t blue_mask_size;         // Direct Color的蓝色屏蔽位宽
    uint8_t blue_field_position;    //蓝色屏蔽位的起始位置
    uint8_t rsv_mask_size;          // Direct Color的保留色屏蔽位宽
    uint8_t rsv_field_position;     //保留色屏蔽位的起始位置
    uint8_t direct_color_mode_info; // Direct Color模式属性

    // VBE2.0以上版本强制提供的信息
    uint32_t phys_base_ptr; //平坦帧缓存区模式的起始物理地址
    uint32_t reserved1;     //保留，必须为0
    uint16_t reserved2;     //保留，必须为0

    // VBE3.0以上版本强制提供的信息
    uint16_t lin_bytes_per_scan_line;  //线性模式的每条扫描线占用字节数
    uint8_t bnk_number_of_image_pages; //块模式的图像页数量
    uint8_t lin_number_of_image_pages; //线性模式的图像页数量
    uint8_t lin_red_mask_size;         // Direct Color的红色屏蔽位宽（线性模式）
    uint8_t lin_red_field_position;    //红色屏蔽位的起始位置（线性模式）
    uint8_t lin_green_mask_size;       // Direct Color的绿色屏蔽位宽（线性模式）
    uint8_t lin_green_field_position;  //绿色屏蔽位的起始位置（线性模式）
    uint8_t lin_blue_mask_size;        // Direct Color的蓝色屏蔽位宽（线性模式）
    uint8_t lin_blue_field_position;   //蓝色屏蔽位的起始位置（线性模式）
    uint8_t lin_rsv_mask_size;         // Direct Color的保留色屏蔽位宽（线性模式）
    uint8_t lin_rsv_field_position;    //保留色屏蔽位的起始位置（线性模式）
    uint32_t max_pixel_clock;          //图像模式的最大像素时钟
    uint8_t reserved3[189];            // mode_info_block剩余空间
};

#define REFRESH_INTERVAL 15UL // 启动刷新帧缓冲区任务的时间间隔

/**
 * @brief VBE帧缓存区的地址重新映射
 * 将帧缓存区映射到地址SPECIAL_MEMOEY_MAPPING_VIRT_ADDR_BASE处
 */
void init_frame_buffer()
{
    kinfo("Re-mapping VBE frame buffer...");

    uint64_t global_CR3 = (uint64_t)get_CR3();

    struct multiboot_tag_framebuffer_info_t info;
    int reserved;

    video_frame_buffer_info.vaddr = SPECIAL_MEMOEY_MAPPING_VIRT_ADDR_BASE + FRAME_BUFFER_MAPPING_OFFSET;
    mm_map_proc_page_table(global_CR3, true, video_frame_buffer_info.vaddr, __fb_info.framebuffer_addr,
                           video_frame_buffer_info.size, PAGE_KERNEL_PAGE | PAGE_PWT | PAGE_PCD, false, true, false);

    flush_tlb();
    kinfo("VBE frame buffer successfully Re-mapped!");
}

/**
 * @brief video守护进程, 按时刷新帧缓冲区
 * @param unused
 * @return int
 */
int video_refresh_daemon(void *unused)
{
    // 初始化锁, 这个锁只会在daemon中使用
    spin_init(&daemon_refresh_lock);

    for (;;)
    {
        if (clock() >= video_refresh_expire_jiffies)
        {
            video_refresh_expire_jiffies = cal_next_n_ms_jiffies(REFRESH_INTERVAL << 1);

            if (likely(video_refresh_target != NULL))
            {
                spin_lock(&daemon_refresh_lock);
                memcpy((void *)video_frame_buffer_info.vaddr, (void *)video_refresh_target->vaddr,
                       video_refresh_target->size);
                spin_unlock(&daemon_refresh_lock);
            }
        }
        video_daemon_pcb->flags &= ~PROC_RUNNING;
        sched();
    }

    return 0;
}

/**
 * @brief 唤醒video的守护进程
 */
void video_refresh_framebuffer(void *data)
{
    if (unlikely(video_daemon_pcb == NULL))
        return;

    process_wakeup(video_daemon_pcb);
}

/**
 * @brief 初始化显示模块，需先低级初始化才能高级初始化
 * @param level 初始化等级
 * false -> 低级初始化：不使用double buffer
 * true ->高级初始化：增加double buffer的支持
 * @return int
 */
int video_reinitialize(bool level) // 这个函数会在main.c调用, 保证 video_init() 先被调用
{
    if (level == false)
        init_frame_buffer();
    else
    {
        // 计算开始时间
        video_refresh_expire_jiffies = cal_next_n_ms_jiffies(10 * REFRESH_INTERVAL);

        // 创建video守护进程
        video_daemon_pcb = kthread_run(&video_refresh_daemon, NULL, CLONE_FS | CLONE_SIGNAL);
        video_daemon_pcb->virtual_runtime = 0; // 特殊情况， 最高优先级， 以后再改

        // 启用屏幕刷新软中断
        register_softirq(VIDEO_REFRESH_SIRQ, &video_refresh_framebuffer, NULL);

        raise_softirq(VIDEO_REFRESH_SIRQ);
    }
    return 0;
}

/**
 * @brief 设置帧缓冲区刷新目标
 *
 * @param buf
 * @return int
 */
int video_set_refresh_target(struct scm_buffer_info_t *buf)
{

    unregister_softirq(VIDEO_REFRESH_SIRQ);
    // todo: 在completion实现后，在这里等待其他刷新任务完成，再进行下一步。

    // int counter = 100;

    // while ((get_softirq_pending() & (1 << VIDEO_REFRESH_SIRQ)) && counter > 0)
    // {
    //     --counter;
    //     usleep(1000);
    // }
    // kdebug("buf = %#018lx", buf);
    video_refresh_target = buf;
    register_softirq(VIDEO_REFRESH_SIRQ, &video_refresh_framebuffer, NULL);
    raise_softirq(VIDEO_REFRESH_SIRQ);
}

/**
 * @brief 初始化显示驱动
 *
 * @return int
 */
int video_init()
{

    memset(&video_frame_buffer_info, 0, sizeof(struct scm_buffer_info_t));
    memset(&__fb_info, 0, sizeof(struct multiboot_tag_framebuffer_info_t));
    video_refresh_target = NULL;

    io_mfence();
    // 从multiboot2获取帧缓冲区信息
    int reserved;
    multiboot2_iter(multiboot2_get_Framebuffer_info, &__fb_info, &reserved);
    io_mfence();

    // 初始化帧缓冲区信息结构体
    if (__fb_info.framebuffer_type == 2)
    {
        video_frame_buffer_info.bit_depth = 8; // type=2时，width和height是按照字符数来表示的，因此depth=8
        video_frame_buffer_info.flags |= SCM_BF_TEXT;
    }
    else
    {
        video_frame_buffer_info.bit_depth = __fb_info.framebuffer_bpp;
        video_frame_buffer_info.flags |= SCM_BF_PIXEL;
    }

    video_frame_buffer_info.flags |= SCM_BF_FB;
    video_frame_buffer_info.width = __fb_info.framebuffer_width;
    video_frame_buffer_info.height = __fb_info.framebuffer_height;
    io_mfence();

    video_frame_buffer_info.size =
        video_frame_buffer_info.width * video_frame_buffer_info.height * ((video_frame_buffer_info.bit_depth + 7) / 8);
    // 先临时映射到该地址，稍后再重新映射
    video_frame_buffer_info.vaddr = 0xffff800003000000;
    mm_map_phys_addr(video_frame_buffer_info.vaddr, __fb_info.framebuffer_addr, video_frame_buffer_info.size,
                     PAGE_KERNEL_PAGE | PAGE_PWT | PAGE_PCD, false);

    io_mfence();
    char init_text2[] = "Video driver initialized.";
    for (int i = 0; i < sizeof(init_text2) - 1; ++i)
        uart_send(COM1, init_text2[i]);

    return 0;
}

/**
 * @brief 获取vbe的信息
 *
 */
void get_vbe_info()
{
    struct vbe_info_block vbe_info;
    memcpy(vbe_info.vbe_signature, "VBE2", 5);
    struct vbe_info_block *ptr = &vbe_info;
    uint64_t phys_ptr = virt_2_phys(ptr);

    __asm__ __volatile__("movq $0x00,%%rax \n\t"
                         "movq %%rax, %%rsi \n\t"
                         "movq %1, %%rdi \n\t"
                         "movq $0x4f00, %%rax \n\t"
                         "int  $0x10 \n\t"
                        //  "cmpw  $0x004f, %%ax \n\t"
                         "movq  %%rsi, %%rax \n\t"
                         "movq  %%rax,%0"
                         : "=m"(phys_ptr)
                         : "m"(phys_ptr)
                         : "memory", "rax", "rsi", "rdi");
    struct vbe_info_block *virt_ptr = (struct vbe_info_block *)phys_2_virt(ptr);
    kdebug("signature:%s\nvideo_mode_ptr:%d\n", virt_ptr->vbe_signature, virt_ptr->video_mode_ptr);
    kdebug("oem_string_ptr:%d\n", virt_ptr->oem_string_ptr);
}

/**
 * @brief 设置textmode
 */
void set_textmode()
{
    // __asm__ __volatile__("movq $0x4F02, %%rax \n\t"
    //                      "movq $0x410C, %%rbx \n\t"
    //                      "int $0x10" ::
    //                          : "rax", "rbx");
}

/**
 * @brief 设置pixel模式
 */
void set_pixelmode()
{
    // __asm__ __volatile__("movq $0x4F02, %%rax \n\t"
    //                      "movq $0x411B, %%rbx \n\t"
    //                      "int $0x10" ::
    //                          : "rax", "rbx");
}