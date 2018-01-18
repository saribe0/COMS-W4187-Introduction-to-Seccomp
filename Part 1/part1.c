/////////////////////////////////////////////
//
// Sam Beaulieu
// COMS 4187: Security Architecture and Engineering
//
// Homework 1, Part 1
// Exmples from the following link used for reference:
// http://man7.org/linux/man-pages/man3/seccomp_rule_add.3.html
//
//////////////////////////////////////////////

#include <fcntl.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/mman.h>

// Handler to catch any system calls and indicate they were caught
void sig_handler(int signo)
{
        printf("=== Caught an invalid system call.\n");
}

int main(int argc, char *argv[])
{
        printf("Unrestricted - Preparing interface.\n");
        int rc = -1;

        // Prepare filter context
        scmp_filter_ctx filter;
        filter = seccomp_init(SCMP_ACT_TRAP);

        if (filter == NULL)
                goto out;

        // Prepare the signal handler
        signal(SIGSYS, sig_handler);

        // Open a file for use later
        int fd = open("file.text", O_RDWR|O_CREAT|O_TRUNC, 00777);
        if (fd < 0)
                goto out; 

        // Add seccomp rules to not allow anything but read, write, and close
        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0) < 0)
                goto out;

        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0)
                goto out;

        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0) 
                goto out;

        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) < 0)
                goto out;

        if (seccomp_rule_add(filter, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0)
                goto out;
        
        
        // Load the filter
        if (seccomp_load(filter) < 0) 
                goto out;       
        
        printf("Rules have been added and loaded. Now testing signal calls\n");
        
        // Indicate that an illegal call is to be attempted
        printf("@ Trying a write system call.\n");
        write(fd, "About to try to close the file.\n", 32);

        printf("@ Trying an open system call.\n");
        open("file3", O_RDWR|O_CREAT, 00777);

        printf("@ Trying a read system call.\n");
        char buf[40];
        read(fd, buf, 32);

        printf("@ Trying a close system call.\n");
        close(fd); 

        printf("@ Trying a dup system call.\n");
        dup2(1, 3);

        printf("@ Trying a fork system call.\n");
        fork();

        printf("@ Trying an mmap system call.\n");
        mmap(NULL, 5, 0, 0, 3, 4);

out: 
        printf("Testing over, cleaning up and exiting.\n");
        seccomp_release(filter);
        return 0;
}
