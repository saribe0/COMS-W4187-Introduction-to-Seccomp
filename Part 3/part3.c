/////////////////////////////////////////////
//
// Sam Beaulieu
// COMS 4187: Security Architecture and Engineering
//
// Homework 1, Part 3
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

// Handler to catch any system calls and indicate they were caught
void sig_handler(int signo)
{       
        printf("=== Caught an invalid system call.\n");
}

int main(int argc, char *argv[])
{
        printf("Unrestricted - Preparing interface.\n");
        int rc = -1;
        int fd_outside_filter = open("file_opened_pre_filter.txt", O_RDWR | O_CREAT, 00777);

        // Prepare filter context
        scmp_filter_ctx filter;
        filter = seccomp_init(SCMP_ACT_ALLOW);

        if (filter == NULL)
                goto out;

        // Prepare the signal handler
        signal(SIGSYS, sig_handler);

        // Add seccomp rule to restrict the open model - Specifically this traps open calls used with the create file mode
        if (seccomp_rule_add(filter, SCMP_ACT_TRAP, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_CREAT, O_CREAT)) < 0)
                goto out;
        
        // Add seccomp rule to restrict the open model - Specifically this traps open calls used with the write only mode
        if (seccomp_rule_add(filter, SCMP_ACT_TRAP, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_WRONLY, O_WRONLY)) < 0)
                goto out;

        // Add seccomp rule to restrict the open model - Specifically this traps open calls used with the read write mode
        if (seccomp_rule_add(filter, SCMP_ACT_TRAP, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_RDWR, O_RDWR)) < 0)
                goto out;

        // Add seccomp rule to restrict the open model - Specifically this traps open calls used with exclusive open mode
        if (seccomp_rule_add(filter, SCMP_ACT_TRAP, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, O_EXCL, O_EXCL)) < 0)
                goto out;
        
        // Add seccomp rule to restrict the write model - Specifically this traps write calls made to files
        if (seccomp_rule_add(filter, SCMP_ACT_TRAP, SCMP_SYS(write), 1, SCMP_A0(SCMP_CMP_GT, 2)) < 0)
                goto out;

        // Load the filter
        if (seccomp_load(filter) < 0)
                goto out;

        printf("Rules have been added and loaded. Now testing signal calls.\n");

        printf("@ Trying to use the open system call in read only mode.\n");
        int fd = open("test1.txt", O_RDONLY);
        if (fd > 2) {
                printf("--- Successfully opened with fd = %i. Closing.\n", fd);
                close(fd);
        }
        
        printf("@ Trying to use the open system call in read only mode with create enabled. (Should fail)\n");
        fd = open("test2.txt", O_WRONLY | O_CREAT);
        if (fd > 2) {
                printf("--- Successfully opened with fd = %i. Closing.\n", fd);
                close(fd);
        }
        
        printf("@ Trying to use the open system call in read and write mode. (Should fail)\n");
        fd = open("test2.txt", O_RDWR);
        if (fd > 2) {
                printf("--- Successfully opened with fd = %i. Closing.\n", fd);
                close(fd);
        }

        printf("@ Trying to use the open system call in write only mode. (Should fail)\n");
        fd = open("test2.txt", O_WRONLY);
        if (fd > 2) {
                printf("--- Successfully opened with fd = %i. Closing.\n", fd);
                close(fd);
        }

        printf("@ Trying to use the open system call in read and write mode with create enabled. (Should fail)\n");
        fd = open("test2.txt", O_RDWR | O_CREAT);
        if (fd > 2) {
                printf("--- Successfully opened with fd = %i. Closing.\n", fd);
                close(fd);
        }

        printf("@ Trying to use the open system call in write only mode with create enabled. (Should fail)\n");
        fd = open("test2.txt", O_WRONLY | O_CREAT);
        if (fd > 2) {
                printf("--- Successfully opened with fd = %i. Closing.\n", fd);
                close(fd);
        }

        printf("@ Trying to use the open system call in read and write only mode with o_excl enabled. (Should fail)\n");
        fd = open("test2.txt", O_RDWR | O_EXCL);
        if (fd > 2) {
                printf("--- Successfully opened with fd = %i. Closing.\n", fd);
                close(fd);
        }

        printf("@ Trying to use the open system call in write only mode with o_excl enabled. (Should fail)\n");
        fd = open("test2.txt", O_WRONLY | O_EXCL);
        if (fd > 2) {
                printf("--- Successfully opened with fd = %i. Closing.\n", fd);
                close(fd);
        }

        printf("Opening a file in read only for further testing...\n");
        fd = open("test2.txt", O_RDONLY);

        printf("@ Trying to use the read system call with the open file.\n");
        char buf[30];
        if (read(fd, buf, 10) == 10) {
                printf("--- Successfully read from fd = %i. Closing.\n", fd);
                close(fd);
        }

        printf("@ Trying to use the write system call with the open file. (Should fail)\n");
        if (write(fd, buf, 10) == 10) {
                printf("--- Successfully wrote to fd = %i. Closing.\n", fd);
                close(fd);
        }

        printf("The next tests try to write to a file opened (in O_RDWR) before the filter was loaded.\n");

        printf("@ Trying to use the write system call with the file. (Should fail)\n");
        if (write(fd_outside_filter, buf, 10) == 10) {
                printf("--- Successfully wrote to fd = %i. Closing.\n", fd_outside_filter);
                close(fd_outside_filter);
        }

out:
        printf("Testing over, cleaning up and exiting.\n");
        seccomp_release(filter);
        return 0;
}
