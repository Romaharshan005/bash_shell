# Shell Assignment 

## Assignment 2 and Assignment 3 combined

A shell is implemented in C as per the requirements.

### Funcations

- Display requirement:
    - Displayed just like the normal bash terminal.

- Builtin Commands:
    - First the three basic bash commands are implemented which are 'cd', 'echo' and 'pwd'.
    - Flags like “.”, “..” and “~” are implemented in 'cd'.
    - Tabs and spaces are handled in 'echo'.

- ls command:
    - Flags like "-a" and "-l" are also implemented in ls.
    - Multiple flags and directory names can be tested. 

- System commands with and without arguments:
    - Foreground processes.
    - Background processes.

- pinfo command (user-defined):
    - This function prints the process info of the current running program, if the PID is not given.
    - If PID is given, the porcess info regarding the corresponding PID is given.

- Finished Background Processes:
    - If the background process is exited then the shell must displays the appropriate message to the user.

- repeat Command:
    - This command is responsible for executing the given instruction multiple times.

- Input/Output Redirection:
    - Implemented the symbols <, > and >>, the output of commands, usually written to stdout, can be redirected to another file, or the input taken from a file other than stdin. Both input and output redirection can be used simultaneously. 

- Command Pipelines:
    - A pipe, identified by |, redirects the output of the command on the left as input to the command on the right. 

-  I/O Redirection within Command Pipelines:
    - Input/output redirection can occur within command pipelines.

-  User-defined Commands:
    - This command prints a list of all currently running background processes spawned by the shell.
    - Along with their job number (a sequential number assigned by your shell), process ID and their state, which can either be running or stopped.

- Signal Handling:
    - CTRL-Z It should push any currently running foreground job into the background, and change its state from running to stopped. This should have no effect on the shell if there is no foreground process running.
    - CTRL-C It should interrupt any currently running foreground job, by sending it the SIGINT signal. This should have no effect on the shell if there is no foreground process running.
    - CTRL-D It should log you out of your shell, without having any effect on the actual terminal.