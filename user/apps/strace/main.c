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
    pid_t child;
    int status;
    struct user_regs_struct regs;
    int orig_rax;

    child = fork();
    if (child == 0)
    {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        // execl("/bin/ls", "/bin/ls", NULL);
        // execv("about", NULL);
        printf("child begins\n");
        for (int i = 0; i < 10; i++)
        {
            printf("child %d\n", i);
            sleep(1);
        }

        exit(0);
    }
    else
    {

        while (1)
        {
            int r = wait(&status); // 接收被子进程发送过来的 SIGCHLD 信号
            printf("r = %d\n", r);
            if (r != -1)
            {
                break;
            }
        }
        printf("father begins\n"); // 打印rax寄存器的值
        int i = 0;
        while (i++ < 10)
        {
            // 1. 发送 PTRACE_SYSCALL 命令给被跟踪进程 (调用系统调用前，可以获取系统调用的参数)
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);

            wait(&status); // 接收被子进程发送过来的 SIGCHLD 信号
            if (WIFEXITED(status))
            { // 如果子进程退出了, 那么终止跟踪
                break;
            }
            printf("%d\n", PTRACE_GETREGS);
            ptrace(0x4204, child, 0, &regs); // 获取被跟踪进程寄存器的值

            orig_rax = regs.orig_rax; // 获取rax寄存器的值

            printf("syscall: %s\n", orig_rax); // 打印rax寄存器的值

            // 2. 发送 PTRACE_SYSCALL 命令给被跟踪进程 (调用系统调用后，可以获取系统调用的返回值)
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);

            wait(&status); // 接收被子进程发送过来的 SIGCHLD 信号
            if (WIFEXITED(status))
            { // 如果子进程退出了, 那么终止跟踪
                break;
            }
        }
    }

    return 0;
}
