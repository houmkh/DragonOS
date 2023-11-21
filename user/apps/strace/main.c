// #include <sys/ptrace.h>
// #include <sys/user.h>
// #include <stdio.h>
// #include <sys/types.h>
// #include <unistd.h>
// #define NULL 0
// int main(int argc, char *argv[])
// {
//     pid_t child;
//     int status;
//     struct user_regs_struct regs;
//     int orig_rax;
//     char *path = argv[1];
//     child = fork();
//     if (child == 0)
//     {
//         ptrace(PTRACE_TRACEME, 0, NULL, NULL);
//         execl(path, NULL, NULL);
//         exit(0);
//     }
//     else
//     {
//         wait(&status); // 接收被子进程发送过来的 SIGCHLD 信号

//         while (1)
//         {
//             // 1. 发送 PTRACE_SYSCALL 命令给被跟踪进程 (调用系统调用前，可以获取系统调用的参数)
//             ptrace(PTRACE_SYSCALL, child, NULL, NULL);

//             wait(&status); // 接收被子进程发送过来的 SIGCHLD 信号
//             if (WIFEXITED(status))
//             { // 如果子进程退出了, 那么终止跟踪
//                 break;
//             }

//             ptrace(PTRACE_GETREGS, child, 0, &regs); // 获取被跟踪进程寄存器的值

//             orig_rax = regs.orig_rax; // 获取rax寄存器的值

//             printf("syscall: %s()\n", find_syscall_symbol(orig_rax)); // 打印rax寄存器的值

//             // 2. 发送 PTRACE_SYSCALL 命令给被跟踪进程 (调用系统调用后，可以获取系统调用的返回值)
//             ptrace(PTRACE_SYSCALL, child, NULL, NULL);

//             wait(&status); // 接收被子进程发送过来的 SIGCHLD 信号
//             if (WIFEXITED(status))
//             { // 如果子进程退出了, 那么终止跟踪
//                 break;
//             }
//         }
//     }

//     return 0;
// }
