/*
 * Python Bridge Module
 * Data analysis and rapid prototyping via Python
 */

#include "python_bridge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int python_initialized = 0;

int python_bridge_init(void) {
    if (python_initialized) {
        return 0;
    }
    
    Py_Initialize();
    
    if (!Py_IsInitialized()) {
        return -1;
    }
    
    // Add current directory to Python path
    PyRun_SimpleString(
        "import sys\n"
        "import os\n"
        "script_dir = os.path.dirname(os.path.abspath(sys.argv[0])) if sys.argv else '.'\n"
        "if script_dir not in sys.path:\n"
        "    sys.path.insert(0, script_dir)\n"
    );
    
    // Initialize embedded analysis module
    PyRun_SimpleString(
        "# Embedded Python analysis module\n"
        "import json\n"
        "import subprocess\n"
        "from datetime import datetime\n"
        "\n"
        "class DeviceAnalyzer:\n"
        "    def __init__(self):\n"
        "        self.data = {}\n"
        "        self.analysis_results = {}\n"
        "\n"
        "    def collect_system_info(self):\n"
        "        info = {}\n"
        "        try:\n"
        "            with open('/proc/cpuinfo') as f:\n"
        "                info['cpuinfo'] = f.read()[:2000]\n"
        "        except:\n"
        "            pass\n"
        "        try:\n"
        "            with open('/proc/meminfo') as f:\n"
        "                info['meminfo'] = f.read()[:2000]\n"
        "        except:\n"
        "            pass\n"
        "        try:\n"
        "            info['lsusb'] = subprocess.check_output(['lsusb'], stderr=subprocess.DEVNULL).decode()[:3000]\n"
        "        except:\n"
        "            info['lsusb'] = 'lsusb not available'\n"
        "        self.data['system'] = info\n"
        "        return info\n"
        "\n"
        "    def analyze_usb_devices(self, raw_data=None):\n"
        "        devices = []\n"
        "        if raw_data:\n"
        "            # Parse raw USB data\n"
        "            lines = raw_data.split('\\n')\n"
        "            current = {}\n"
        "            for line in lines:\n"
        "                if 'ID' in line:\n"
        "                    parts = line.split('ID')[-1].strip().split()\n"
        "                    if len(parts) >= 2:\n"
        "                        vid_pid = parts[0]\n"
        "                        desc = ' '.join(parts[1:])\n"
        "                        devices.append({'vid_pid': vid_pid, 'description': desc})\n"
        "        else:\n"
        "            try:\n"
        "                output = subprocess.check_output(['lsusb'], stderr=subprocess.DEVNULL).decode()\n"
        "                for line in output.split('\\n'):\n"
        "                    if 'ID' in line:\n"
        "                        parts = line.split('ID')[-1].strip().split()\n"
        "                        if len(parts) >= 2:\n"
        "                            vid_pid = parts[0]\n"
        "                            desc = ' '.join(parts[1:])\n"
        "                            vid, pid = vid_pid.split(':')\n"
        "                            devices.append({\n"
        "                                'vid': vid,\n"
        "                                'pid': pid,\n"
        "                                'description': desc,\n"
        "                                'vid_pid': vid_pid\n"
        "                            })\n"
        "            except:\n"
        "                pass\n"
        "        self.analysis_results['usb_devices'] = devices\n"
        "        return devices\n"
        "\n"
        "    def get_vendor_info(self, vid):\n"
        "        vendors = {\n"
        "            '046d': 'Logitech',\n"
        "            '0424': 'Microchip',\n"
        "            '0781': 'SanDisk',\n"
        "            '0951': 'Kingston',\n"
        "            '0bda': 'Realtek',\n"
        "            '1058': 'Western Digital',\n"
        "            '1235': 'Focusrite',\n"
        "            '1a86': 'QinHeng',\n"
        "            '8086': 'Intel',\n"
        "            '8087': 'Intel',\n"
        "            '0c45': 'Sonix',\n"
        "            '03eb': 'Atmel',\n"
        "            '2341': 'Arduino',\n"
        "            '2e8a': 'Raspberry Pi',\n"
        "            '0483': 'STMicroelectronics',\n"
        "        }\n"
        "        return vendors.get(vid.lower(), 'Unknown')\n"
        "\n"
        "    def generate_summary(self):\n"
        "        summary = {\n"
        "            'timestamp': datetime.now().isoformat(),\n"
        "            'device_count': len(self.analysis_results.get('usb_devices', [])),\n"
        "            'categories': self._categorize_devices()\n"
        "        }\n"
        "        return summary\n"
        "\n"
        "    def _categorize_devices(self):\n"
        "        devices = self.analysis_results.get('usb_devices', [])\n"
        "        categories = {}\n"
        "        for dev in devices:\n"
        "            vid = dev.get('vid', 'unknown')\n"
        "            vendor = self.get_vendor_info(vid)\n"
        "            if vendor not in categories:\n"
        "                categories[vendor] = []\n"
        "            categories[vendor].append(dev)\n"
        "        return categories\n"
        "\n"
        "    def export_json(self, filename=None):\n"
        "        if filename is None:\n"
        "            filename = 'device_analysis.json'\n"
        "        data = {\n"
        "            'timestamp': datetime.now().isoformat(),\n"
        "            'raw_data': self.data,\n"
        "            'analysis': self.analysis_results\n"
        "        }\n"
        "        with open(filename, 'w') as f:\n"
        "            json.dump(data, f, indent=2)\n"
        "        return filename\n"
        "\n"
        "analyzer = DeviceAnalyzer()\n"
    );
    
    python_initialized = 1;
    return 0;
}

void python_bridge_cleanup(void) {
    if (python_initialized && Py_IsInitialized()) {
        Py_Finalize();
        python_initialized = 0;
    }
}

char* python_analyze_data(void) {
    if (!python_initialized) {
        return strdup("Python not initialized");
    }
    
    char *result = malloc(8192);
    if (!result) return NULL;
    
    strcpy(result, "Data Analysis (Python-powered)\n");
    strcat(result, "==============================\n\n");
    
    // Run analysis
    PyObject *main_module = PyImport_AddModule("__main__");
    PyObject *global_dict = PyModule_GetDict(main_module);
    
    // Call analyzer.collect_system_info()
    PyRun_SimpleString("analyzer.collect_system_info()");
    
    // Call analyzer.analyze_usb_devices()
    PyRun_SimpleString("usb_data = analyzer.analyze_usb_devices()");
    
    // Get USB device count
    PyObject *usb_data = PyDict_GetItemString(global_dict, "usb_data");
    if (usb_data) {
        Py_ssize_t count = PyList_Size(usb_data);
        snprintf(result + strlen(result), 512, "USB Devices Found: %zd\n\n", count);
        
        strcat(result, "Device List:\n");
        for (Py_ssize_t i = 0; i < count && i < 15; i++) {
            PyObject *dev = PyList_GetItem(usb_data, i);
            if (dev && PyDict_Check(dev)) {
                PyObject *vid_obj = PyDict_GetItemString(dev, "vid");
                PyObject *pid_obj = PyDict_GetItemString(dev, "pid");
                PyObject *desc_obj = PyDict_GetItemString(dev, "description");
                
                const char *vid = vid_obj ? PyUnicode_AsUTF8(vid_obj) : "??";
                const char *pid = pid_obj ? PyUnicode_AsUTF8(pid_obj) : "??";
                const char *desc = desc_obj ? PyUnicode_AsUTF8(desc_obj) : "Unknown";
                
                snprintf(result + strlen(result), 512, "  %zd. [%s:%s] %s\n", 
                         i + 1, vid, pid, desc);
            }
        }
    }
    
    // Generate summary
    PyRun_SimpleString("summary = analyzer.generate_summary()");
    PyObject *summary = PyDict_GetItemString(global_dict, "summary");
    
    if (summary && PyDict_Check(summary)) {
        strcat(result, "\n--- Analysis Summary ---\n");
        
        PyObject *ts_obj = PyDict_GetItemString(summary, "timestamp");
        if (ts_obj) {
            snprintf(result + strlen(result), 512, "Timestamp: %s\n", PyUnicode_AsUTF8(ts_obj));
        }
        
        PyObject *cat_obj = PyDict_GetItemString(summary, "categories");
        if (cat_obj && PyDict_Check(cat_obj)) {
            strcat(result, "\nBy Vendor:\n");
            PyObject *key, *value;
            Py_ssize_t pos = 0;
            while (PyDict_Next(cat_obj, &pos, &key, &value)) {
                if (PyUnicode_Check(key) && PyList_Check(value)) {
                    snprintf(result + strlen(result), 512, "  %s: %zd device(s)\n",
                             PyUnicode_AsUTF8(key), PyList_Size(value));
                }
            }
        }
    }
    
    return result;
}

char* python_analyze_usb_data(const char *raw_data) {
    if (!python_initialized) {
        return strdup("Python not initialized");
    }
    
    // Create Python string from C string
    PyObject *py_raw_data = PyUnicode_FromString(raw_data);
    if (!py_raw_data) {
        return strdup("Error converting data");
    }
    
    // Set as variable in Python
    PyObject *main_module = PyImport_AddModule("__main__");
    PyObject *global_dict = PyModule_GetDict(main_module);
    PyDict_SetItemString(global_dict, "raw_usb_data", py_raw_data);
    Py_DECREF(py_raw_data);
    
    // Analyze
    char *result = malloc(4096);
    if (!result) return NULL;
    
    strcpy(result, "USB Data Analysis\n");
    strcat(result, "==================\n\n");
    
    PyRun_SimpleString("parsed = analyzer.analyze_usb_devices(raw_usb_data)");
    
    PyObject *parsed = PyDict_GetItemString(global_dict, "parsed");
    if (parsed) {
        Py_ssize_t count = PyList_Size(parsed);
        snprintf(result + strlen(result), 512, "Parsed %zd devices from raw data\n", count);
    }
    
    return result;
}

char* python_generate_report(void) {
    if (!python_initialized) {
        return strdup("Python not initialized");
    }
    
    PyRun_SimpleString("report_file = analyzer.export_json()");
    
    char *result = malloc(512);
    if (!result) return NULL;
    
    strcpy(result, "Report generated successfully\n");
    strcat(result, "Output: device_analysis.json\n");
    
    return result;
}

char* python_export_json(const char *data) {
    if (!python_initialized) {
        return strdup("Python not initialized");
    }
    
    // Export current analysis to JSON
    PyRun_SimpleString("analyzer.export_json('device_export.json')");
    
    return strdup("Data exported to device_export.json");
}

char* python_execute_script(const char *script_path) {
    if (!python_initialized) {
        return strdup("Python not initialized");
    }
    
    FILE *fp = fopen(script_path, "r");
    if (!fp) {
        char *result = malloc(256);
        snprintf(result, 256, "Cannot open script: %s", script_path);
        return result;
    }
    
    int ret = PyRun_SimpleFile(fp, script_path);
    fclose(fp);
    
    if (ret != 0) {
        return strdup("Script execution failed");
    }
    
    return strdup("Script executed successfully");
}

char* python_execute_code(const char *code) {
    if (!python_initialized) {
        return strdup("Python not initialized");
    }
    
    int ret = PyRun_SimpleString(code);
    if (ret != 0) {
        return strdup("Code execution failed");
    }
    
    return strdup("Code executed successfully");
}
