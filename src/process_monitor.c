/*
 * модуль мониторинга процессов
 * реальное время, минимальные зависимости, прямой доступ к /proc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <time.h>
#include <ctype.h>
#include "process_monitor.h"

/* чтение файла целиком в буфер */
static int read_file(const char *path, char *buf, size_t size) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    
    size_t n = fread(buf, 1, size - 1, f);
    buf[n] = '\0';
    fclose(f);
    return (int)n;
}

/* парсинг целого из строки */
static long parse_long(const char *s) {
    return strtol(s, NULL, 10);
}

/* получение имени пользователя по uid */
static void get_username(uid_t uid, char *buf, size_t size) {
    struct passwd *pw = getpwuid(uid);
    if (pw) {
        strncpy(buf, pw->pw_name, size - 1);
        buf[size - 1] = '\0';
    } else {
        snprintf(buf, size, "%d", uid);
    }
}

/* парсинг /proc/pid/stat */
static int parse_proc_stat(int pid, proc_stat_t *stat) {
    char path[256];
    char buf[1024];
    char *p;
    
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    if (read_file(path, buf, sizeof(buf)) < 0) {
        return -1;
    }
    
    /* pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime priority nice num_threads itrealvalue starttime vsize rss rsslim startcode endcode startstack kstkesp kstkeip signal blocked sigignore sigcatch wchan nswap cnswap exit_signal processor rt_priority policy delayacct_blkio_ticks guest_time cguest_time */
    
    p = strrchr(buf, ')');
    if (!p) return -1;
    *p = '\0';
    
    /* имя процесса */
    char *name_start = strchr(buf, '(');
    if (name_start) {
        strncpy(stat->comm, name_start + 1, sizeof(stat->comm) - 1);
        stat->comm[sizeof(stat->comm) - 1] = '\0';
    }
    
    p++;
    while (*p == ' ') p++;
    
    /* парсим остальные поля */
    char state;
    long ppid, pgrp, session, tty_nr, tpgid, flags;
    unsigned long minflt, cminflt, majflt, cmajflt, utime, stime;
    long cutime, cstime, priority, nice, num_threads, itrealvalue;
    unsigned long long starttime;
    unsigned long vsize;
    long rss;
    
    sscanf(p, "%c %ld %ld %ld %ld %ld %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld",
           &state, &ppid, &pgrp, &session, &tty_nr, &tpgid, &flags,
           &minflt, &cminflt, &majflt, &cmajflt, &utime, &stime,
           &cutime, &cstime, &priority, &nice, &num_threads, &itrealvalue,
           &starttime, &vsize, &rss);
    
    stat->state = state;
    stat->ppid = ppid;
    stat->utime = utime;
    stat->stime = stime;
    stat->num_threads = num_threads;
    stat->vsize = vsize;
    stat->rss = rss * 4096; /* rss в страницах по 4kb */
    
    return 0;
}

/* парсинг /proc/pid/status */
static int parse_proc_status(int pid, proc_status_t *status) {
    char path[256];
    char buf[4096];
    char *line;
    
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    if (read_file(path, buf, sizeof(buf)) < 0) {
        return -1;
    }
    
    memset(status, 0, sizeof(*status));
    
    line = strtok(buf, "\n");
    while (line) {
        if (strncmp(line, "Uid:", 4) == 0) {
            sscanf(line, "Uid:\t%ld", &status->uid);
        } else if (strncmp(line, "Gid:", 4) == 0) {
            sscanf(line, "Gid:\t%ld", &status->gid);
        } else if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line, "VmRSS:\t%ld", &status->vm_rss);
        } else if (strncmp(line, "VmSize:", 7) == 0) {
            sscanf(line, "VmSize:\t%ld", &status->vm_size);
        } else if (strncmp(line, "Threads:", 8) == 0) {
            sscanf(line, "Threads:\t%ld", &status->threads);
        } else if (strncmp(line, "voluntary_ctxt_switches:", 24) == 0) {
            sscanf(line, "voluntary_ctxt_switches:\t%lu", &status->voluntary_ctxt_switches);
        } else if (strncmp(line, "nonvoluntary_ctxt_switches:", 25) == 0) {
            sscanf(line, "nonvoluntary_ctxt_switches:\t%lu", &status->nonvoluntary_ctxt_switches);
        }
        line = strtok(NULL, "\n");
    }
    
    return 0;
}

/* чтение командной строки */
static int read_cmdline(int pid, char *buf, size_t size) {
    char path[256];
    int n, i;
    
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    n = read_file(path, buf, size);
    
    if (n > 0) {
        /* заменяем \0 на пробелы для читаемости */
        for (i = 0; i < n - 1; i++) {
            if (buf[i] == '\0') buf[i] = ' ';
        }
        buf[n] = '\0';
    } else {
        /* если cmdline пуст, используем имя из stat */
        proc_stat_t st;
        if (parse_proc_stat(pid, &st) == 0) {
            snprintf(buf, size, "[%s]", st.comm);
            n = strlen(buf);
        } else {
            buf[0] = '\0';
        }
    }
    
    return n;
}

/* подсчет открытых файлов */
static int count_open_fds(int pid) {
    char path[256];
    struct dirent *entry;
    DIR *dir;
    int count = 0;
    
    snprintf(path, sizeof(path), "/proc/%d/fd", pid);
    dir = opendir(path);
    if (!dir) return -1;
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.') {
            count++;
        }
    }
    
    closedir(dir);
    return count;
}

/* подсчет сетевых соединений процесса */
static int count_connections(int pid) {
    char path[256];
    char buf[8192];
    int count = 0;
    FILE *f;
    
    /* проверяем tcp соединения */
    snprintf(path, sizeof(path), "/proc/%d/net/tcp", pid);
    f = fopen(path, "r");
    if (f) {
        /* пропускаем заголовок */
        fgets(buf, sizeof(buf), f);
        while (fgets(buf, sizeof(buf), f)) {
            /* ищем established соединения */
            if (strstr(buf, "01 ")) { /* 01 = established */
                count++;
            }
        }
        fclose(f);
    }
    
    return count;
}

/* получение информации о процессе */
int proc_get_info(int pid, proc_info_t *info) {
    proc_stat_t stat;
    proc_status_t status;
    char path[256];
    struct stat st;
    
    memset(info, 0, sizeof(*info));
    info->pid = pid;
    
    /* проверяем существование */
    snprintf(path, sizeof(path), "/proc/%d", pid);
    if (stat(path, &st) != 0) {
        return -1;
    }
    
    /* время запуска */
    info->start_time = st.st_ctime;
    
    /* stat */
    if (parse_proc_stat(pid, &stat) != 0) {
        return -1;
    }
    
    strncpy(info->name, stat.comm, sizeof(info->name) - 1);
    info->name[sizeof(info->name) - 1] = '\0';
    info->state = stat.state;
    info->ppid = stat.ppid;
    info->num_threads = stat.num_threads;
    info->vsize = stat.vsize;
    info->rss = stat.rss;
    
    /* status для uid и доп. информации */
    if (parse_proc_status(pid, &status) == 0) {
        info->uid = status.uid;
        info->gid = status.gid;
        info->vm_rss_kb = status.vm_rss;
        info->ctx_switches = status.voluntary_ctxt_switches + status.nonvoluntary_ctxt_switches;
    }
    
    /* имя пользователя */
    get_username(info->uid, info->username, sizeof(info->username));
    info->is_root = (info->uid == 0);
    
    /* командная строка */
    read_cmdline(pid, info->cmdline, sizeof(info->cmdline));
    
    /* открытые файлы */
    info->open_files = count_open_fds(pid);
    
    /* соединения */
    info->connections = count_connections(pid);
    
    /* cpu usage estimation - требует двух замеров, здесь примерный */
    info->cpu_percent = 0.0f; /* будет вычислено отдельно */
    
    return 0;
}

/* получение списка всех процессов */
int proc_list_all(int **pids, int *count) {
    DIR *dir;
    struct dirent *entry;
    int *list = NULL;
    int n = 0;
    int capacity = 256;
    
    dir = opendir("/proc");
    if (!dir) return -1;
    
    list = malloc(capacity * sizeof(int));
    if (!list) {
        closedir(dir);
        return -1;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        if (isdigit(entry->d_name[0])) {
            int pid = atoi(entry->d_name);
            
            if (n >= capacity) {
                capacity *= 2;
                int *new_list = realloc(list, capacity * sizeof(int));
                if (!new_list) {
                    free(list);
                    closedir(dir);
                    return -1;
                }
                list = new_list;
            }
            
            list[n++] = pid;
        }
    }
    
    closedir(dir);
    
    *pids = list;
    *count = n;
    return 0;
}

/* сортировка процессов по памяти */
static int compare_by_memory(const void *a, const void *b) {
    const proc_info_t *pa = (const proc_info_t *)a;
    const proc_info_t *pb = (const proc_info_t *)b;
    return (pb->vm_rss_kb - pa->vm_rss_kb);
}

/* сортировка по cpu */
static int compare_by_cpu(const void *a, const void *b) {
    const proc_info_t *pa = (const proc_info_t *)a;
    const proc_info_t *pb = (const proc_info_t *)b;
    return (int)((pb->cpu_percent - pa->cpu_percent) * 100);
}

/* получение топ процессов по памяти */
int proc_get_top_memory(proc_info_t **procs, int *count, int n) {
    int *pids;
    int pid_count;
    proc_info_t *list;
    int i, valid_count = 0;
    
    if (proc_list_all(&pids, &pid_count) != 0) {
        return -1;
    }
    
    list = malloc(pid_count * sizeof(proc_info_t));
    if (!list) {
        free(pids);
        return -1;
    }
    
    for (i = 0; i < pid_count; i++) {
        if (proc_get_info(pids[i], &list[valid_count]) == 0) {
            valid_count++;
        }
    }
    
    free(pids);
    
    /* сортировка */
    qsort(list, valid_count, sizeof(proc_info_t), compare_by_memory);
    
    /* возвращаем запрошенное количество */
    if (n > valid_count) n = valid_count;
    
    *procs = malloc(n * sizeof(proc_info_t));
    if (!*procs) {
        free(list);
        return -1;
    }
    
    memcpy(*procs, list, n * sizeof(proc_info_t));
    *count = n;
    
    free(list);
    return 0;
}

/* получение топ процессов по cpu */
int proc_get_top_cpu(proc_info_t **procs, int *count, int n) {
    /* требуется двойной замер, упрощенная версия */
    int *pids;
    int pid_count;
    proc_info_t *list;
    int i, valid_count = 0;
    
    if (proc_list_all(&pids, &pid_count) != 0) {
        return -1;
    }
    
    list = malloc(pid_count * sizeof(proc_info_t));
    if (!list) {
        free(pids);
        return -1;
    }
    
    for (i = 0; i < pid_count; i++) {
        if (proc_get_info(pids[i], &list[valid_count]) == 0) {
            /* эвристика для cpu: больше ctx switches = больше cpu */
            list[valid_count].cpu_percent = list[valid_count].ctx_switches / 1000.0f;
            if (list[valid_count].cpu_percent > 100.0f) {
                list[valid_count].cpu_percent = 100.0f;
            }
            valid_count++;
        }
    }
    
    free(pids);
    
    qsort(list, valid_count, sizeof(proc_info_t), compare_by_cpu);
    
    if (n > valid_count) n = valid_count;
    
    *procs = malloc(n * sizeof(proc_info_t));
    if (!*procs) {
        free(list);
        return -1;
    }
    
    memcpy(*procs, list, n * sizeof(proc_info_t));
    *count = n;
    
    free(list);
    return 0;
}

/* поиск подозрительных процессов */
int proc_find_suspicious(proc_info_t **procs, int *count) {
    int *pids;
    int pid_count;
    proc_info_t *list;
    int i, suspicious_count = 0;
    int capacity = 64;
    
    if (proc_list_all(&pids, &pid_count) != 0) {
        return -1;
    }
    
    list = malloc(capacity * sizeof(proc_info_t));
    if (!list) {
        free(pids);
        return -1;
    }
    
    for (i = 0; i < pid_count; i++) {
        proc_info_t info;
        if (proc_get_info(pids[i], &info) != 0) continue;
        
        int suspicious = 0;
        
        /* от root с сетью */
        if (info.is_root && info.connections > 0 && info.ppid != 1) {
            suspicious = 1;
        }
        
        /* скрытое имя */
        if (strlen(info.name) < 2 || strcmp(info.name, ".") == 0) {
            suspicious = 1;
        }
        
        /* очень много открытых файлов */
        if (info.open_files > 1000) {
            suspicious = 1;
        }
        
        /* высокое потребление памяти */
        if (info.vm_rss_kb > 1024 * 1024) { /* > 1GB */
            suspicious = 1;
        }
        
        if (suspicious) {
            if (suspicious_count >= capacity) {
                capacity *= 2;
                proc_info_t *new_list = realloc(list, capacity * sizeof(proc_info_t));
                if (!new_list) break;
                list = new_list;
            }
            list[suspicious_count++] = info;
        }
    }
    
    free(pids);
    
    *procs = list;
    *count = suspicious_count;
    return 0;
}

/* построение дерева процессов */
int proc_build_tree(proc_tree_t **tree, int *count) {
    int *pids;
    int pid_count;
    proc_tree_t *nodes;
    int i;
    
    if (proc_list_all(&pids, &pid_count) != 0) {
        return -1;
    }
    
    nodes = calloc(pid_count, sizeof(proc_tree_t));
    if (!nodes) {
        free(pids);
        return -1;
    }
    
    for (i = 0; i < pid_count; i++) {
        proc_stat_t stat;
        nodes[i].pid = pids[i];
        
        if (parse_proc_stat(pids[i], &stat) == 0) {
            nodes[i].ppid = stat.ppid;
            strncpy(nodes[i].name, stat.comm, sizeof(nodes[i].name) - 1);
        }
    }
    
    free(pids);
    
    *tree = nodes;
    *count = pid_count;
    return 0;
}

/* вывод информации о процессе */
void proc_print_info(const proc_info_t *info) {
    printf("pid: %d\n", info->pid);
    printf("  имя: %s\n", info->name);
    printf("  пользователь: %s (%s)\n", info->username, info->is_root ? "root" : "user");
    printf("  состояние: %c\n", info->state);
    printf("  родитель: %d\n", info->ppid);
    printf("  потоков: %d\n", info->num_threads);
    printf("  память rss: %ld kb\n", info->vm_rss_kb);
    printf("  вирт. память: %lu bytes\n", info->vsize);
    printf("  открыто файлов: %d\n", info->open_files);
    printf("  соединений: %d\n", info->connections);
    printf("  переключений: %lu\n", info->ctx_switches);
    printf("  cpu: %.1f%%\n", info->cpu_percent);
    printf("  cmdline: %.60s...\n", info->cmdline);
}

/* освобождение памяти */
void proc_free_list(proc_info_t *procs) {
    free(procs);
}

void proc_free_tree(proc_tree_t *tree) {
    free(tree);
}
