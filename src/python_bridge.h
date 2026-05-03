#ifndef PYTHON_BRIDGE_H
#define PYTHON_BRIDGE_H

#include <Python.h>

// функции python моста
int python_bridge_init(void);
void python_bridge_cleanup(void);

// функции анализа данных
char* python_analyze_data(void);
char* python_analyze_usb_data(const char *raw_data);
char* python_generate_report(void);
char* python_export_json(const char *data);

// выполнение скриптов
char* python_execute_script(const char *script_path);
char* python_execute_code(const char *code);

#endif // python_bridge_h
