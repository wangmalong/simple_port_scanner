#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include "portscan.h"
#include "captpacket.h"


pid_t pid;

void sig_child()
{
	wait(pid);
	return;
}

void port_scan( char type, char *dst_ip_str )
{


    signal(SIGCHLD, sig_child);

    pid = fork();

    if(0 > pid)
	{
		perror("fork error\n");
		exit(1);
	}
	else if(0 != pid){              /* parent process */
        capture_package( dst_ip_str );
    }else{                          /* child process */
        sleep(2);
        build_packet(type, dst_ip_str);
    }

}
