#ifndef TERMINAL_H
#define TERMINAL_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <limits.h>
#include <math.h>
#include <fcntl.h>

#define TOK_DELIM " \t\n\a\r"
#define RL_BUFSIZE 1024
#define PATH_SIZE 256
#define COMM_DELIM ";"
#define NC "\033[0m"

void child_handler();
int cd_fun(char **args);
int pwd_fun(char **args);
int echo_fun(char **args);
int ls_fun(char **args);
int pinfo_fun(char **args);
int repeat_fun(char **args);
char *relative_path_fun(char *cur_dir);
char *absolute_path_fun(char *given_path);
int exe(char **cmd);
int launch_arguements(char **args);
char **get_arguements(char *line, int decide);
char *read_command_line();
void print_prompt_screen();
void shell_representation_func();
void signal_C_handler(int signum);
void signal_Z_handler(int signum);
int redirection_func(char **args, int num, int input, int output, int commands_done);
int piping_func(char **args);
void job_done(int *arr, int x);
int piping_process(char *array[], int input, int output, int commands_done);
int builtins_execution(char **args, int input, int output);
int job_fun(char **argv);
int sig_fun(char **args);
int fg_fun(char **args);
int bg_fun(char **args);
int fg_pid;

int background_order_len, background_order[32768], foreground;
int process_statuses[1000000]; // -1 means not exist, 1 means running, 0 means stopped
int job_array[32768];
char *background_processes[32768];
char *home;
char *rel_path;

#endif
