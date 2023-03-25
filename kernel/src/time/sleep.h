#pragma once

#include <common/glib.h>
#include <process/ptrace.h>
#include <common/time.h>

// /**
//  * @brief 休眠指定时间
//  *
//  * @param rqtp 指定休眠的时间
//  * @param rmtp 返回的剩余休眠时间
//  * @return int
//  */
// int nanosleep(const struct timespec *rqtp, struct timespec *rmtp);

extern int nano_sleep_c(const struct timespec *sleep_time, struct timespec *rm_time);
extern int rs_us_sleep(useconds_t usec);
// /**
//  * @brief 睡眠指定时间
//  *
//  * @param usec 微秒
//  * @return int
//  */
// int usleep(useconds_t usec);