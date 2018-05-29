#ifndef __CONFIG__
#define __CONFIG__

#define CMD_KILL "kill"
#define CMD_WHOAMI "whoami"
#define CMD_EXEC "exec"
#define CMD_DOWNLOAD "download"
#define CMD_HELP "help"

#define CMD_EXIT "exit"
#define CMD_NO_RECON "Command not recognized\n"

#define ERR_EPERM "Operation not permitted\n"
#define ERR_ESRCH "No process with this PID\n"
#define ERR_UNCAUGHT "Undefined error\n"
#define ERR_WHOAMI "Failed to get PWID\n"

#define CMD_HELP_OUT "List of commands:\n\n  kill <PID>\n    Kills the process with the given PID.\n  whoami\n    Returns the current username that is executing the backdoor.\n  exec <program>\n    Executes the given

#define CMD_SUCCESS "Command executed correctly!\n"
#define CMD_WHOAMI_RET "Current user: "


#endif
