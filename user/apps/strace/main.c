#include <sys/ptrace.h>
#include <sys/user.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <signal.h>

int main()
{
    // printf("this is strace test/n");
    pid_t child;
    int *status = (int *)malloc(sizeof(int));
    struct user_regs_struct regs;
    int orig_rax;
    // char *path = argv[1];
    printf("fork child\n");
    child = fork();

    if (child == 0)
    {
        printf("child = %d\n", getpid());

        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        // sleep(10);
        kill(5, SIGCONT);

        while (1)
        {
        }
        // execl(path, "", NULL);
        printf("child exit\n");
        exit(0);
    }
    else if (child > 0)
    {

        printf("parent = %d\n", getpid());
        printf("parent wait sigchld\n");
        wait(status); // 接收被子进程发送过来的 SIGCHLD 信号
        // printf("get_sigchld\n");
        while (1)
        {
            /* code */
        }

        // for (int i = 0; i < 10; ++i)
        // {
        //     // 1. 发送 PTRACE_SYSCALL 命令给被跟踪进程 (调用系统调用前，可以获取系统调用的参数)
        //     printf("PTRACE_SYSCALL:\n");
        //     ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        //     printf("wait:\n");

        //     wait(&status); // 接收被子进程发送过来的 SIGCHLD 信号
        //     if (WIFEXITED(status))
        //     { // 如果子进程退出了, 那么终止跟踪
        //         break;
        //     }
        //     printf("PTRACE_GETREGS:\n");

        //     ptrace(PTRACE_GETREGS, child, 0, &regs); // 获取被跟踪进程寄存器的值

        //     orig_rax = regs.orig_rax; // 获取rax寄存器的值
        //     // 打印系统调用号
        //     printf("syscall: %d\n", orig_rax); // 打印rax寄存器的值
        //     printf("PTRACE_SYSCALL:\n");

        //     // 2. 发送 PTRACE_SYSCALL 命令给被跟踪进程 (调用系统调用后，可以获取系统调用的返回值)
        //     ptrace(PTRACE_SYSCALL, child, NULL, NULL);

        //     // wait(&status); // 接收被子进程发送过来的 SIGCHLD 信号
        //     if (WIFEXITED(status))
        //     { // 如果子进程退出了, 那么终止跟踪
        //         break;
        //     }
        // }
    }
    else
    {
        printf("fork fail\n");
    }

    return 0;
}
