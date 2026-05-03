/*
 * заголовок модуля мониторинга процессов
 */

#ifndef PROCESS_MONITOR_H
#define PROCESS_MONITOR_H

#include <sys/types.h>
#include <stdint.h>

/* структура информации о процессе */
typedef struct {
    int pid;
    int ppid;
    char name[64];
    char username[32];
    uid_t uid;
    gid_t gid;
    char state;
    int is_root;
    
    /* память */
    long vm_rss_kb;      /* resident set size в kb */
    unsigned long vsize; /* виртуальная память */
    unsigned long rss;   /* resident set size в bytes */
    
    /* cpu */
    float cpu_percent;
    unsigned long utime; /* пользовательское время */
    unsigned long stime; /* системное время */
    
    /* характеристики */
    int num_threads;
    unsigned long ctx_switches;
    int open_files;
    int connections;
    time_t start_time;
    
    /* командная строка */
    char cmdline[1024];
} proc_info_t;

/* структура для дерева процессов */
typedef struct {
    int pid;
    int ppid;
    char name[64];
    /* для построения дерева можно добавить указатели на детей */
} proc_tree_t;

/* вспомогательные структуры для парсинга */
typedef struct {
    char comm[64];
    char state;
    long ppid;
    unsigned long utime;
    unsigned long stime;
    long num_threads;
    unsigned long vsize;
    long rss;
} proc_stat_t;

typedef struct {
    long uid;
    long gid;
    long vm_rss;
    long vm_size;
    long threads;
    unsigned long voluntary_ctxt_switches;
    unsigned long nonvoluntary_ctxt_switches;
} proc_status_t;

/* функции */

/* получение информации о процессе */
int proc_get_info(int pid, proc_info_t *info);

/* получение списка всех pid */
int proc_list_all(int **pids, int *count);

/* топ процессов по памяти */
int proc_get_top_memory(proc_info_t **procs, int *count, int n);

/* топ процессов по cpu */
int proc_get_top_cpu(proc_info_t **procs, int *count, int n);

/* поиск подозрительных процессов */
int proc_find_suspicious(proc_info_t **procs, int *count);

/* построение дерева процессов */
int proc_build_tree(proc_tree_t **tree, int *count);

/* вывод информации */
void proc_print_info(const proc_info_t *info);

/* освобождение памяти */
void proc_free_list(proc_info_t *procs);
void proc_free_tree(proc_tree_t *tree);

#endif /* PROCESS_MONITOR_H */
