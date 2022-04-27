#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <string.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>

#include "terminal.h"

int num = 0;
int actual_stdin;
int actual_stdout;
int signal_z;

int (*user_defined_function[])(char **) = {&cd_fun, &pwd_fun, &echo_fun, &ls_fun, &pinfo_fun, &repeat_fun, &job_fun, &fg_fun, &bg_fun, &sig_fun};

int number_of_user_defined_functions = 10;

char *user_defined_strings[] = {"cd", "pwd", "echo", "ls", "pinfo", "repeat", "jobs", "fg", "bg", "sig"};

int builtins_execution(char **args, int input, int output)
{
    int i = -1, return_value = 0;
    while (++i < number_of_user_defined_functions)
    {
        if (strcmp(args[0], user_defined_strings[i]) == 0)
        {
            //we pass the whole command into builtin functions list
            return_value = (*user_defined_function[i])(args);
            break;
        }
    }
    return return_value;
}

void job_done(int *arr, int x)
{
    for (int i = x + 1; i < 32768; i++)
    {
        job_array[i - 1] = job_array[i];
    }
    num--;
}

int cd_fun(char **args)
{
    if (args[1] == NULL)
    {
        fprintf(stderr, "mysh: expected argument to \"cd\"\n");
        fprintf(stderr, "mysh: type \"cd\" --help for learn proper usage\n");
    }
    else
    {
        if (strcmp(args[1], "--help") == 0)
        {
            printf("Usage: cd <path to directory>\n");
        }
        else
        {
            char *temp = absolute_path_fun(args[1]);
            if (chdir(temp) != 0)
            {
                perror("mysh");
            }
        }
    }
    return 1;
}

int pwd_fun(char **args)
{
    char *pwd = (char *)malloc(1024);
    getcwd(pwd, (size_t)1024);
    printf("%s\n", pwd);
    return 1;
}

int echo_fun(char **args)
{
    int i = 0;
    while (args[++i] != NULL)
    {
        char *words = args[i];
        if (words[0] == '$')
        {
            char *var = words + 1;
            char *value = getenv(var);
            if (!value)
                printf("%s ", words);
            else
                printf("%s ", value);
        }
        else
            printf("%s ", words);
    }
    printf("\n");
    return 1;
}

int repeat_fun(char **args)
{
    int i = 0;
    int repeatitions;
    while (args[++i] != NULL)
    {
        if (i == 1)
        {
            repeatitions = atoi(args[i]);
        }
    }

    char *buff[1000];
    int count = 0;
    for (int k = 2;; k++)
    {
        if (args[k] == NULL)
        {
            buff[count++] = args[k];
            break;
        }
        buff[count++] = args[k];
    }

    for (int j = 0; j < repeatitions; j++)
    {
        launch_arguements(buff);
    }
    return 1;
}

int piping_process(char *array[], int input, int output, int commands_done)
{
    pid_t pid = fork();
    if (pid < 0)
    {
        fprintf(stderr, "Child process could not be created\n");
        return 0;
    }
    else if (pid == 0)
    {
        if (input != 0)
            close(0);
        if (output != 1)
            close(1);
        dup2(input, 0);
        dup2(output, 1); // set the inp/op sources accordingly

        char *word[2];
        word[0] = array[0];
        word[1] = NULL;

        if (execvp(array[0], array) < 0)
        {
            fprintf(stderr, "%s:command could not be executed\n", array[0]);
            exit(0);
        }
    }
    else
    {
        wait(NULL);
        dup2(actual_stdin, 0);
        dup2(actual_stdout, 1);
        return 1;
    }
}

int exe(char **cmd)
{
    int cmd_len = -1, return_value = 1;
    char **args; //arguments of command
    while (cmd[++cmd_len] != NULL)
    {
        args = get_arguements(cmd[cmd_len], 1);
        int flag = 0, i = -1;
        if (args[0] == NULL)
        {
            return_value = 0;
            flag++;
        }
        if (flag == 0)
            return_value = launch_arguements(args);
        free(args);
        if (return_value == 0)
            return 0;
    }
    return 1;
}

char *relative_path_fun(char *cur_dir)
{
    int cur_size = strlen(cur_dir), home_size = strlen(home);
    char *arr = "~";
    if (cur_size == home_size && strcmp(cur_dir, home) == 0)
        return arr;
    else if (cur_size < home_size)
    {
        return cur_dir;
    }
    else
    {
        char *temp = (char *)malloc((size_t)home_size);
        for (int i = 0; i < home_size; ++i)
        {
            temp[i] = cur_dir[i];
        }
        temp[home_size] = 0;
        if (strcmp(temp, home) != 0)
            return cur_dir;
        free(temp);
        char *relative_path = (char *)malloc((size_t)PATH_SIZE);
        if (!relative_path)
        {
            fprintf(stderr, "Allocaiton Error \n");
            exit(EXIT_FAILURE);
        }
        relative_path[0] = '~';
        int count = 1;
        for (int i = home_size; i < cur_size; ++i)
        {
            relative_path[count++] = cur_dir[i];
        }
        relative_path[count] = '\0';

        return relative_path;
    }
}

char *absolute_path_fun(char *given_path)
{
    char *temp = malloc((size_t)1024);
    int i = 0, start = 0;
    if (given_path[0] == '~')
    {
        while (home[i] != '\0')
        {
            temp[i] = home[i];
            i++;
        }
        start = 1;
    }
    int j = i;
    while (given_path[start] != '\0')
    {
        temp[j++] = given_path[start++];
    }
    temp[j] = '\0';
    return temp;
}

void child_handler()
{
    int status, index;
    pid_t wpid = waitpid(-1, &status, WNOHANG | WUNTRACED);
    for (int i = 0; i < 32768; i++)
    {
        if (job_array[i] == wpid)
        {
            index = i;
            break;
        }
    }
    if (wpid > 0 && WIFEXITED(status) > 0)
    {
        fprintf(stderr, "%s with pid %d exited normally\n", background_processes[wpid], wpid);
        process_statuses[wpid] = -1;
        background_processes[wpid] = '\0';
        job_done(job_array, index);
    }
    else if (wpid > 0 && WIFSIGNALED(status) == 1)
    {
        fprintf(stderr, "\n%s with pid %d exited abnormally due to signal %d\n", background_processes[wpid], wpid, WTERMSIG(status));
        process_statuses[wpid] = -1;
        background_processes[wpid] = '\0';
        job_done(job_array, index);
    }
    return;
}

void signal_C_handler(int signum)
{
    char *col1 = "\033[31;1m";
    char *col2 = NC;
    if (foreground > 0)
    {
        kill(foreground, SIGINT);
        foreground = -1;
    }
    printf("\n%sKeyboard interrupt, PRESS ENTER to continue...%s\n", col1, col2);
    fflush(stdout);
}

void signal_Z_handler(int signum)
{
    job_array[num++] = fg_pid;
    process_statuses[fg_pid] = 0; // 0 means stopped
    printf("\nStopped : [%d] \n", fg_pid);
    kill(fg_pid, SIGTSTP);
    signal_z = 1;
    fflush(stdout);
    return;
}

int launch_arguements(char **args)
{
    signal_z = 0;
    //args is arguments of space spearated single command
    int background = 0, redirection = 0, piping = 0;
    int i, j;
    char *stopcmd;
    char *array[200];
    for (i = 0; args[i] != NULL; i++)
    {
        if (strcmp(args[i], "quit") == 0 || strcmp(args[i], "exit") == 0)
            exit(EXIT_SUCCESS);
        for (j = 0; args[i][j] != '\0'; j++)
        {
            if (args[i][j] == '>' || args[i][j] == '<')
                redirection = 1;
            if (args[i][j] == '|')
                piping = 1;
        }
    }
    if (piping == 1)
    {
        piping_func(args);
        return 1;
    }
    else if (redirection == 1)
    {
        int len = 0;
        while (args[len])
        {
            len++;
        }
        /*       int left = -1;
        int right = -1;
        for (int k = 0; k < len; k++)
        {
            if (strcmp(args[k], "<") == 0)
            {
                left = k;
            }
            else if (strcmp(args[k], ">") == 0 || strcmp(args[k], ">>") == 0)
            {
                right = k;
            }
        }
        int fd_in, fd_out;
        if (left == -1)
        {
            fd_in = 0;
        }
        else
        {
            int fd_1 = open(args[left + 1], O_RDONLY);
            fd_in = fd_1;
        }
        if (right == -1)
        {
            fd_out = 0;
        }
        else
        {
            int fd_2;
            if (strcmp(args[right], ">") == 0)
            {
                fd_2 = open(args[right + 1], O_WRONLY | O_CREAT | O_TRUNC);
                fd_out = fd_2;
            }
            else if (strcmp(args[right], ">>") == 0)
            {
                fd_2 = open(args[right + 1], O_WRONLY | O_CREAT | O_APPEND);
                fd_out = fd_2;
            }
        }*/
        redirection_func(args, len, 0, 1, len);
        return 1;
    }
    i = -1;
    while (args[++i])
    {
        if (strcmp(args[i], "&") == 0)
        {
            args[i] = 0;
            background = 1;
            break;
        }
        array[i] = args[i];
    }

    //normal commands without pipes/redirection
    int return_value = builtins_execution(args, 0, 1);
    if (return_value == 1)
        return 1;
    pid_t cur_pid, w;
    int status, flag = 0;
    signal(SIGTSTP, signal_Z_handler);
    cur_pid = fork();
    if (cur_pid == -1)
    {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    if (cur_pid == 0)
    {
        //child process
        if (background == 1)
        {
            if (strcmp(args[0], "vim") == 0 || strcmp(args[0], "vi") == 0)
            {
                exit(EXIT_SUCCESS);
            }
            else
            {
                setpgid(0, 0);
            }
        }
        if (execvp(args[0], args) == -1)
        {
            perror("mysh");
        }
        exit(EXIT_FAILURE);
    }
    else
    {
        if (background == 1)
        {
            if (strcmp(args[0], "vim") != 0 && strcmp(args[0], "vi") != 0)
            {
                process_statuses[cur_pid] = 2; // 1 means running
                printf("%d\n", cur_pid);
                background_order[background_order_len++] = cur_pid;
                background_processes[cur_pid] = malloc(1024);
                strcpy(background_processes[cur_pid], args[0]);
                job_array[num++] = cur_pid;
                return 1;
            }
            else
            {
                process_statuses[cur_pid] = 1; // 1 means running
                printf("\nStopped : [%d] \n", cur_pid);
                background_order[background_order_len++] = cur_pid;
                background_processes[cur_pid] = malloc(1024);
                job_array[num++] = cur_pid;
                strcpy(background_processes[cur_pid], args[0]);
                return 1;
            }
        }
        do
        {
            fg_pid = cur_pid;
            stopcmd = malloc(1024);
            strcpy(stopcmd, args[0]);
            if (signal_z == 0)
            {
                w = waitpid(cur_pid, &status, WUNTRACED | WCONTINUED);
                if (w == -1)
                {
                    perror("waitpid");
                    exit(EXIT_FAILURE);
                }
            }
            else
            {
                background_order[background_order_len++] = fg_pid;
                background_processes[fg_pid] = malloc(1024);
                strcpy(background_processes[fg_pid], args[0]);
                break;
            }
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
        free(stopcmd);
        return 1;
    }
}

int job_fun(char **args)
{
    int i, j = 1;
    int r, s = 0;
    int index;

    for (i = 0; i < 32768; i++)
    {
        //avoid the non existing processes
        if (background_processes[background_order[i]] && process_statuses[background_order[i]] != -1)
        {
            int pid = background_order[i];
            char addr[1000]; //path to stat file
            for (int p = 0; p < 32768; p++)
            {
                if (job_array[p] == pid)
                {
                    index = p;
                    break;
                }
            }
            sprintf(addr, "/proc/%d/stat", pid);
            FILE *f;
            if (!(f = fopen(addr, "r")))
            {
                fprintf(stderr, "job Error : No such process found\n");
                return 1;
            }
            char status, name[200];
            fscanf(f, "%d %s %c", &pid, name, &status);
            if (args[1])
            {
                if (strcmp(args[1], "-r") == 0)
                {
                    r = 1;
                }
                if (strcmp(args[1], "-s") == 0)
                {
                    s = 1;
                }
                if (r == 1)
                {
                    if (status == 'R')
                    {
                        printf("[%d]", index + 1);
                        printf("\tRunning");
                        printf("\t%s [%d]\n", background_processes[background_order[i]], background_order[i]);
                    }
                    if (status == 'S')
                    {
                        printf("[%d]", index + 1);
                        printf("\tRunning");
                        printf("\t%s [%d]\n", background_processes[background_order[i]], background_order[i]);
                    }
                    if (status == 'Z')
                    {
                        printf("[%d]", index + 1);
                        printf("\tRunning");
                        printf("\t%s [%d]\n", background_processes[background_order[i]], background_order[i]);
                    }
                    r--;
                }
                else if (s == 1)
                {
                    if (status == 'T')
                    {
                        printf("[%d]", index + 1);
                        printf("\tStopped");
                        printf("\t%s [%d]\n", background_processes[background_order[i]], background_order[i]);
                    }
                    s--;
                }
            }
            else
            {
                printf("[%d]", index + 1);
                if (status == 'R')
                    printf("\tRunning");
                if (status == 'S')
                    printf("\tRunning");
                if (status == 'Z')
                    printf("\tRunning");
                if (status == 'T')
                    printf("\tStopped");

                printf("\t%s [%d]\n", background_processes[background_order[i]], background_order[i]);
            }
        }
    }
    return 1;
}

int fg_fun(char **args)
{
    int pid, done = 0;
    signal_z = 0;
    char *stopcmd;
    int index;
    signal(SIGTSTP, signal_Z_handler);
    if (!args[1] || args[2])
    {
        fprintf(stderr, "Incorrect number of arguments\n");
        fprintf(stderr, "correct usage: fg <job_no>\n");
    }
    else
    {
        int j = 0, job_id = atoi(args[1]);
        for (int i = 0; i < 32768; i++)
        {
            if (background_processes[background_order[i]] && process_statuses[background_order[i]] != -1)
            {
                j++;
                if (j == job_id)
                {
                    //to be run in foreground so better remove it from jobs array
                    pid = background_order[i];
                    for (int p = 0; p < 32768; p++)
                    {
                        if (job_array[p] == pid)
                        {
                            index = p;
                            break;
                        }
                    }
                    foreground = pid;
                    process_statuses[pid] = 1;
                    // background_order_len--;
                    fg_pid = pid;
                    stopcmd = malloc(1024);
                    strcpy(stopcmd, background_processes[pid]);
                    int status;
                    kill(pid, SIGCONT);
                    waitpid(pid, &status, WUNTRACED);
                    if (WIFEXITED(status) || WIFSIGNALED(status))
                        process_statuses[pid] = -1;
                    job_done(job_array, index);
                    done = 1;
                    break;
                }
            }
        }
        if (done == 0)
            perror("process does not exist with given job id");
    }
    return 1;
}

int bg_fun(char **args)
{
    int pid, done = 0;
    if (!args[1])
    {
        perror("Insuffecient arguments");
    }
    else
    {
        int j = 0, job_id = atoi(args[1]);
        for (int i = 0; i < 32768; i++)
        {
            if (background_processes[background_order[i]] && process_statuses[background_order[i]] != -1)
            {
                j++;
                if (j == job_id)
                {
                    pid = background_order[i];
                    int status;
                    kill(pid, SIGCONT);
                    process_statuses[pid] = 1; //running
                    done = 1;
                    break;
                }
            }
        }
        if (done == 0)
            perror("process does not exist with given job id");
    }
    return 1;
}

int sig_fun(char **args)
{
    int index;
    if (!args[1] || !args[2])
    {
        fprintf(stderr, "Incorrect number of arguments\n");
        fprintf(stderr, "correct usage: sig <job_no> <cmd>\n");
    }
    int job_num = atoi(args[1]);
    int sig_num = atoi(args[2]);

    int pid = job_array[job_num-1];

    for (int p = 0; p < 32768; p++)
    {
        if (job_array[p] == pid)
        {
            index = p;
            break;
        }
    }

    kill(job_array[job_num - 1], sig_num);

    job_done(job_array, index);

    return 1;
}

int ls_fun(char **args)
{
    int n, begin = 1;
    bool hidden = false, long_format = false;
    int i = 0, allowed = 0;
    while (args[++i])
    {
        if (args[i][0] == '-')
        {
            if (args[1] && strcmp(args[i], "-l") == 0)
            {
                long_format = true;
            }
            else if (args[1] && strcmp(args[i], "-a") == 0)
            {
                hidden = true;
            }
            else if (args[1] && strcmp(args[i], "-la") == 0)
            {
                long_format = true;
                hidden = true;
            }
            else if (args[1] && strcmp(args[i], "-al") == 0)
            {
                long_format = true;
                hidden = true;
            }
            else
            {
                fprintf(stderr, "Unexpected arguments provided to \"ls\"\n");
                return 1;
            }
        }
    }
    i = 1;
    int exit_flag = 0, dir_till_now = 0;
    while (1)
    {
        if ((!args[i] && dir_till_now == 0) || (args[i] && args[i][0] != '-'))
        {
            if (args[i] && args[i][0] != '-')
                dir_till_now++;
            struct passwd *user;
            struct group *group;
            struct tm *tm;
            char *temp;
            DIR *dir_p;
            struct dirent *dir_element;
            struct stat file_information;
            char this_dir[] = ".";
            char date_str[1024];
            if (!args[i])
            {
                temp = this_dir;
                exit_flag++;
            }
            else
                temp = absolute_path_fun(args[i]);
            //if it isn't a directory
            if (!(dir_p = opendir(temp)))
            {
                perror("opendir");
                return 1;
            }

            while (dir_element = readdir(dir_p))
            {
                char *full_path = malloc(1024 * sizeof(char));
                sprintf(full_path, "%s/%s", temp, dir_element->d_name);
                stat(full_path, &file_information);
                char *name = dir_element->d_name;
                if (!hidden && name[0] == '.')
                    continue;
                else
                {
                    if (long_format)
                    {
                        if (S_ISDIR(file_information.st_mode))
                        {
                            printf("d");
                        }
                        else
                        {
                            printf("-");
                        }
                        if (file_information.st_mode & S_IRUSR)
                        {
                            printf("r");
                        }
                        else
                        {
                            printf("-");
                        }
                        if (file_information.st_mode & S_IWUSR)
                        {
                            printf("w");
                        }
                        else
                        {
                            printf("-");
                        }
                        if (file_information.st_mode & S_IXUSR)
                        {
                            printf("x");
                        }
                        else
                        {
                            printf("-");
                        }
                        if (file_information.st_mode & S_IRGRP)
                        {
                            printf("r");
                        }
                        else
                        {
                            printf("-");
                        }
                        if (file_information.st_mode & S_IWGRP)
                        {
                            printf("w");
                        }
                        else
                        {
                            printf("-");
                        }
                        if (file_information.st_mode & S_IXGRP)
                        {
                            printf("x");
                        }
                        else
                        {
                            printf("-");
                        }
                        if (file_information.st_mode & S_IROTH)
                        {
                            printf("r");
                        }
                        else
                        {
                            printf("-");
                        }
                        if (file_information.st_mode & S_IWOTH)
                        {
                            printf("w");
                        }
                        else
                        {
                            printf("-");
                        }
                        if (file_information.st_mode & S_IXOTH)
                        {
                            printf("x");
                        }
                        else
                        {
                            printf("-");
                        }

                        printf(" %4lu ", file_information.st_nlink);

                        if ((user = getpwuid(file_information.st_uid)) != NULL)
                        {
                            printf(" %s", user->pw_name);
                        }
                        else
                        {
                            printf(" %d", file_information.st_uid);
                        }
                        if ((group = getgrgid(file_information.st_gid)) != NULL)
                        {
                            printf(" %s", group->gr_name);
                        }
                        else
                        {
                            printf(" %d", file_information.st_gid);
                        }
                        printf(" %9jd", (__intmax_t)file_information.st_size);
                        tm = localtime(&file_information.st_mtime);
                        strftime(date_str, sizeof(date_str), "%b %d %H:%M", tm);
                        printf(" %s", date_str);
                    }
                    char *col1 = "\033[34;1m";
                    char *col2 = NC;
                    if (S_ISDIR(file_information.st_mode))
                    {
                        printf("%s", col1);
                    }
                    printf(" %s%s\n", dir_element->d_name, col2);
                }
                free(full_path);
            }
        }
        else if (!args[i] && dir_till_now != 0)
            exit_flag++;
        ++i;
        if (exit_flag != 0)
        {
            break;
        }
    }
    return 1;
}

char **get_arguements(char *line, int decide)
{
    char *DELIM;
    if (decide == 0)
        DELIM = COMM_DELIM;
    else
        DELIM = TOK_DELIM;
    size_t buffer_size = RL_BUFSIZE;
    int cmd_buf_size = buffer_size;
    char **cmd = malloc(buffer_size * sizeof(char *));
    //means cmd[i] points to ith character array
    if (!cmd)
    {
        fprintf(stderr, "mysh: Allocaiton Error \n");
        exit(EXIT_FAILURE);
    }
    int i = 0;
    char *string;
    char *command = strtok(line, DELIM);
    // printf("Following is the list of commands found:\n");
    while (1)
    {
        if (command == NULL)
            break;
        if (i >= buffer_size)
        {
            buffer_size += RL_BUFSIZE;
            cmd_buf_size = buffer_size;
            cmd = realloc(cmd, buffer_size);
        }
        if (!cmd)
        {
            fprintf(stderr, "mysh: Allocation Error \n");
            exit(EXIT_FAILURE);
        }
        cmd[i++] = command;
        //printf("%s\n", command); //maybe print or not print this
        command = strtok(NULL, DELIM);
    }
    cmd[i] = NULL;
    return cmd;
}

char *read_command_line()
{
    size_t buffer_size = RL_BUFSIZE;
    char *buf = (char *)malloc(buffer_size);
    if (!buf)
    {
        fprintf(stderr, "Allocaiton Error \n");
        exit(EXIT_FAILURE);
    }
    int i = 0, ch;
    while (1)
    {
        ch = getchar();
        if (ch == EOF)
            exit(0);
        else if (ch == '\n')
        {
            buf[i++] = '\0';
            return buf;
        }
        else
            buf[i++] = ch;

        if (i >= buffer_size)
        {
            buffer_size += RL_BUFSIZE;
            buf = realloc(buf, buffer_size);
            if (!buf)
            {
                fprintf(stderr, "Allocaiton Error \n");
                exit(EXIT_FAILURE);
            }
        }
    }
}

int pinfo_fun(char **args)
{
    char addr[1000]; //path to stat file
    char temp[1000];
    if (args[1])
    {
        sprintf(temp, "/proc/%s/", args[1]);
        sprintf(addr, "/proc/%s/stat", args[1]);
    }
    else
    {
        sprintf(temp, "/proc/%d/", getpid());
        sprintf(addr, "/proc/%d/stat", getpid());
    }
    //pid and process status
    FILE *f;
    if (!(f = fopen(addr, "r")))
    {
        fprintf(stderr, "pinfo Error : No such process found\n");
        return 1;
    }
    int pid;
    char status, name[200];
    char *col1 = "\033[32;1m";
    char *col2 = NC;
    char *col3 = "\033[31;1m";
    char *col4 = "\033[34;1m";
    fscanf(f, "%d %s %c", &pid, name, &status);
    printf("pid -- %s%d%s\n", col1, pid, col2);
    printf("Process Status -- %s%c%s\n", col3, status, col2);
    fclose(f);

    //virtual memory
    long long int v_mem;
    char mem_addr[1000]; //path to statm file
    strcpy(mem_addr, temp);
    strcat(mem_addr, "statm");
    if (!(f = fopen(mem_addr, "r")))
    {
        fprintf(stderr, "pinfo Error : No such process found\n");
        return 1;
    }
    fscanf(f, "%Ld", &v_mem);
    printf("memory -- %Ld {Virtual Memory}\n", v_mem);
    fclose(f);

    //path to executable
    char exec_path[1000], exec_addr[1000] = {0}; //exec_addr is path to exe file
    strcpy(exec_path, temp);
    strcat(exec_path, "exe");
    int len = readlink(exec_path, exec_addr, sizeof(exec_addr));
    if (len >= 0)
    {
        exec_addr[len] = '\n';
        printf("Executable Path -- %s%s%s", col4, exec_addr, col2);
    }
    else
        perror("readlink");
    return 1;
}

void print_prompt_screen()
{
    char *user;
    user = getenv("USER");
    struct utsname sys_details;
    if (uname(&sys_details) != 0)
    {
        perror("uname");
        exit(EXIT_FAILURE);
    }
    char *cur_dir = (char *)malloc(1024);
    if (!cur_dir)
    {
        fprintf(stderr, "Allocaiton Error \n");
        exit(EXIT_FAILURE);
    }
    getcwd(cur_dir, (size_t)1024);
    char *relative_path = relative_path_fun(cur_dir);
    char *col1 = "\033[33;1m";
    char *col2 = NC;
    char *col3 = "\033[34;1m";
    printf("%s%s@%s%s:%s%s> ", col1, user, sys_details.nodename, col3, relative_path, col2);
    free(cur_dir);
}

int piping_func(char **args)
{
    //args: space separated list of arguments of a command
    int pipestr[2], i = -1, j = 0, k = 0, start = 0;
    int num_of_pipes;
    char *array[100];
    while (args[++i])
    {
        if (strcmp(args[i], "|") == 0)
        {
            if (j == 0)
                start = i;
            ++j;
        }
    }
    int cmds = j + 1;
    if (start == 0)
    {
        fprintf(stderr, "mysh: syntax error in command entered\n");
        return 0;
    }
    else
    {
        int l = 0;
        int fd_in = 0, commands_done = 0;
        for (i = 0; i < cmds; ++i)
        {
            j = 0;
            while (args[l])
            {
                if (strcmp(args[l], "|") == 0)
                {
                    l++;
                    break;
                }
                array[j++] = args[l++];
            }
            array[j] = 0;
            pipe(pipestr);
            int return_value = 0, k = -1;

            if (commands_done == 0)
            {
                return_value = redirection_func(array, j, fd_in, pipestr[1], j);
            }
            else if (commands_done == cmds - 1)
            {
                return_value = redirection_func(array, j, fd_in, 1, j);
            }
            else
            {
                return_value = piping_process(array, fd_in, pipestr[1], j);
            }
            if (return_value == 0)
                return 0;
            close(pipestr[1]);
            fd_in = pipestr[0];
            ++commands_done;
        }
    }
    return 1;
}

int redirection_func(char *array[], int len, int input, int output, int commands_done)
{
    //one complete command without any pipes
    array[len] = NULL;
    char output_file1[PATH_SIZE], output_file2[PATH_SIZE], input_file[PATH_SIZE];
    int indirec = 0, outdirec = 0, outappend = 0; //flags for checking
    int i = -1;

    while (array[++i])
    {
        if (strcmp(array[i], "<") == 0)
        {
            if (!array[i + 1])
            {
                fprintf(stderr, "mysh: syntax error: Invalid usage of pipes or redirection\n");
                return 1;
            }
            array[i] = NULL;
            // stdin should become array[i+1]
            strcpy(input_file, array[i + 1]);
            indirec = 1;
        }
        else if (strcmp(array[i], ">") == 0)
        {
            if (!array[i + 1])
            {
                fprintf(stderr, "mysh: syntax error: Invalid usage of pipes or redirection\n");
                return 1;
            }
            array[i] = NULL;
            // stdout should become array[i+1]
            strcpy(output_file1, array[i + 1]);
            outdirec = 1;
        }
        else if (strcmp(array[i], ">>") == 0)
        {
            if (!array[i + 1])
            {
                fprintf(stderr, "mysh: syntax error: Invalid usage of pipes or redirection\n");
                return 1;
            }
            array[i] = NULL;
            //stdout should become array[i+1] and append to file
            strcpy(output_file2, array[i + 1]);
            outappend = 1;
        }
        // array[i] = args[i];
    }

    int fd_inp = input, fd_op = output;
    if (indirec)
    {
        fd_inp = open(input_file, O_RDONLY, 0);
        if (fd_inp < 0)
        {
            perror("Could not open input file");
            return 1;
        }
    }
    if (outdirec)
    {
        fd_op = open(output_file1, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd_op < 0)
        {
            perror("Could not open output file");
            return 1;
        }
    }
    else if (outappend)
    {
        fd_op = open(output_file2, O_APPEND | O_RDWR | O_CREAT, 0644);
        if (fd_op < 0)
        {
            perror("Could not open output file");
            return 1;
        }
    }

    int return_value = 0;
    // it's not a builtin process so exe via execvp
    return_value = piping_process(array, fd_inp, fd_op, commands_done);
    if (return_value == 0)
        return 0;
    return 1;
}

void signal_end_handler(int signum)
{
    return;
}

void shell_representation_func()
{
    char *line;
    char **cmd; //commands array separted by ; in line
    int status = 1;
    while (status)
    {
        signal(SIGINT, signal_C_handler);
        signal(SIGTSTP, signal_end_handler);
        child_handler();
        print_prompt_screen();
        char *line = read_command_line();
        cmd = get_arguements(line, 0);
        status = exe(cmd);
        free(line);
        free(cmd);
    }
}

int main(int argc, char **argv)
{
    background_order_len = 0;
    foreground = -1;
    actual_stdin = dup(0);
    actual_stdout = dup(1);
    for (int i = 0; i < 1000000; ++i)
        process_statuses[i] = -1;
    home = getenv("PWD"); //home needs to the first opened directory
    shell_representation_func();
    return EXIT_SUCCESS;
}