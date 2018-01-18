/////////////////////////////////////////////
//
// Sam Beaulieu
// COMS 4187: Security Architecture and Engineering
//
// Homework 1, Part 2
// Exmples from the following link used for reference:
// http://man7.org/linux/man-pages/man2/seccomp.2.html
//
//////////////////////////////////////////////

#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/mman.h> 

// Macros to match system calls with their associated numbers
// - Numbers were gotten using the SCMP_SYS macro in the libseccomp library
#define WRITE_CALL 1
#define READ_CALL 0
#define CLOSE_CALL 3
#define EXIT_GROUP_CALL 231
#define SIG_RETURN_CALL 15 

// Handler to catch any system calls and indicate they were caught
void sig_handler(int signo)
{       
        printf("=== Caught an invalid system call.\n");
}

int main(int argc, char *argv[])
{
    printf("Unrestricted - Preparing interface.\n");
    int rc = -1;

    // Prepare the signal handler
    signal(SIGSYS, sig_handler);

    // Open a file for use later
    int fd = open("file.text", O_RDWR|O_CREAT|O_TRUNC, 00777);
    if (fd < 0)
        goto out;

    // Create the filter itself
    struct sock_filter filter[] = {

        // First, get the number of the called system call
        // - Loads one word with the right offset from the seccomp_data struct
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),

        // Jump to allow the system call "write" through
        // - Jump if the system call is equal to the write system call
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, WRITE_CALL, 5, 0),

        // Jump to allow the system call "read" through
        // - Jump if the system call is equal to the read system call
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, READ_CALL, 4, 0),

        // Jump to allow the system call "close" through
        // - Jump if the system call is equal to the close system call
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, CLOSE_CALL, 3, 0),

        // Jump to allow the system call "exit_group" through
        // - Jump if the system call is equal to the write system call
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, EXIT_GROUP_CALL, 2, 0),

        // Jump to allow the system call "rt_sigreturn" through
        // - Jump if the system call is equal to the rt_sigreturn system call
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIG_RETURN_CALL, 1, 0),

        // If no jump was made, trap the call and raise the signal
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

        // Destination of system call match to allow the system call
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    // Prepare the filter program
    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    // Assign the proper privileges 
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    {
    return -1;
    }

    // Install the filter
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) 
    {
        return -1;
    }

    printf("Rules have been added and loaded. Now testing signal calls\n");

    printf("@ Trying a write system call.\n");
    write(fd, "Writing to a file part 2.\n", 32);

    printf("@ Trying an open system call.\n");
    open("file3", O_RDWR|O_CREAT, 00777);

    printf("@ Trying a read system call.\n");
    char buf[40];
    read(fd, buf, 32);

    printf("@ Trying a close system call with fd %i.\n", fd);
    close(fd);

    printf("@ Trying a dup system call.\n");
    dup2(1, 3);

    printf("@ Trying a fork system call.\n");
    fork();

    printf("@ Trying an mmap system call.\n");
    mmap(NULL, 5, 0, 0, 3, 4);

out:
    printf("Testing over, exiting.\n");
    return 0;
}