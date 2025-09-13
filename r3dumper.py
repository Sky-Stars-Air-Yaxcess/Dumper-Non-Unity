# -- Copyright (c) 2025 Sky-Stars-Air-Yaxcess
# Repository: https://github.com/Sky-Stars-Air-Yaxcess/Dumper-Non-Unity
# License: GNU General Public License v3.0 (GPL-3.0)
# Do not remove this header. All rights reserved under GPL v3.0.

#tAuthor Script My YouTube Channel Star_Space_Galaxy
#Author Script My GitHub Sky-Stars-Air-Yaxcess
#My YouTube 2 Channel Star_Space_Local_Yaxcess

import subprocess
import sys
import os
import re
import time
import argparse
import logging
import json
import hashlib
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

def setup_logging():
    """Настройка системы логирования"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('radare_dumper.log'),
            logging.StreamHandler()
        ]
    )

def color(text, code):
    """Добавление цветового форматирования к тексту"""
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

MESSAGES = {
    "banner": [
        "R|", "Ra|", "Rad|", "Rada|", "Radar|", "Radare|", "Radare2|",
        "Radare2 |", "Radare2 Du|", "Radare2 Dump|", "Radare2 Dumpe|",
        "Radare2 Dumper|", "Radare2 Dumper"
    ],
    "install_termux": "Installing binutils...",
    "extracting": "Extracting symbols:",
    "saved_to": "Dump saved:",
    "file_not_found": "File not found:",
    "termux_detected": "Termux ready",
    "grant_storage": "Run termux-setup-storage",
    "processing": "Processing...",
    "methods_found": "Methods:",
    "classes_found": "Classes:",
    "time_taken": "Time:",
    "output_dir_created": "Directory created:",
    "missing_binutils": "Binutils missing. Installing...",
    "invalid_path": "Invalid path",
    "storage_permission": "Storage permission needed",
    "select_lib": "Select .so file (or 'q' to quit): ",
    "no_so_files": "No .so files found in script directory",
    "invalid_input": "Invalid input",
    "press_enter": "Press Enter to exit",
    "elf_check_failed": "Not a valid ELF file",
    "arch_detected": "Architecture detected:",
    "cache_used": "Using cached symbols:",
    "export_json": "Exporting JSON metadata:",
    "export_html": "Exporting HTML report:",
    "vtable_analysis": "Analyzing virtual tables...",
    "inheritance_analysis": "Analyzing inheritance relationships...",
    "string_references": "Extracting string references...",
    "cross_references": "Finding cross-references...",
    "type_recovery": "Recovering type information..."
}

def clear_screen():
    """Очистка экрана терминала"""
    os.system('cls' if os.name == 'nt' else 'clear')

def animated_banner():
    """Анимированный баннер"""
    try:
        term_width = os.get_terminal_size().columns
    except OSError:
        term_width = 80
        
    for frame in MESSAGES["banner"]:
        clear_screen()
        padding = " " * ((term_width - len(frame)) // 2)
        print(padding + color(frame, "33;1"))
        time.sleep(0.1)

def is_termux():
    """Проверка, запущен ли скрипт в Termux"""
    return 'com.termux' in os.environ.get('PREFIX', '')

def check_command(cmd):
    """Проверка доступности команды в системе"""
    try:
        return subprocess.run(['command', '-v', cmd], 
                            stdout=subprocess.DEVNULL, 
                            stderr=subprocess.DEVNULL).returncode == 0
    except:
        return False

def install_binutils_termux():
    """Установка binutils в Termux"""
    logging.info(MESSAGES["install_termux"])
    subprocess.run(['pkg', 'update', '-y'], 
                  stdout=subprocess.DEVNULL, 
                  stderr=subprocess.DEVNULL)
    subprocess.run(['pkg', 'install', 'binutils', '-y'], 
                  stdout=subprocess.DEVNULL, 
                  stderr=subprocess.DEVNULL)

def get_so_files(directory=None):
    """Поиск .so файлов в указанной директории"""
    if directory is None:
        directory = os.path.dirname(os.path.abspath(__file__))
    
    so_files = []
    for f in os.listdir(directory):
        full_path = os.path.join(directory, f)
        if f.endswith('.so') and os.path.isfile(full_path):
            so_files.append((f, full_path))
    return so_files

def get_user_input(so_files):
    """Интерактивный выбор файла пользователем"""
    while True:
        try:
            print(color("────୨ৎ────────୨ৎ────", "32"))
            for i, (file, full_path) in enumerate(so_files, 1):
                arch = detect_architecture(full_path)
                print(color(f"[{i}] - {file} ({arch})", "32"))
            print(color("────୨ৎ────────୨ৎ────", "32"))
            
            user_input = input(color(MESSAGES["select_lib"], "35;1")).strip().lower()
            if user_input in ('q', '0', 'quit', 'exit'):
                print("\nExiting...")
                sys.exit(0)
                
            if not user_input.isdigit() or not (1 <= int(user_input) <= len(so_files)):
                print(color(MESSAGES["invalid_input"], "31"))
                continue
                
            return so_files[int(user_input) - 1][1]
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            sys.exit(0)

def is_valid_elf(file_path):
    """Проверка, является ли файл валидным ELF"""
    try:
        with open(file_path, 'rb') as f:
            return f.read(4) == b'\x7fELF'
    except:
        return False

def detect_architecture(file_path):
    """Определение архитектуры ELF файла"""
    try:
        result = subprocess.run(['readelf', '-h', file_path], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'Machine:' in line:
                    return line.split(':')[1].strip()
    except:
        pass
    return "Unknown"

def extract_symbols_advanced(lib_path):
    """Расширенное извлечение символов с использованием нескольких методов"""
    symbols = []
    
    # 1. Основное извлечение символов через readelf
    try:
        result = subprocess.run(['readelf', '-Ws', lib_path], 
                              capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            symbols.extend(result.stdout.splitlines())
    except subprocess.TimeoutExpired:
        logging.warning("readelf symbol extraction timed out")
    
    # 2. Дополнительное извлечение через nm (если доступен)
    if check_command('nm'):
        try:
            result = subprocess.run(['nm', '-D', '--defined-only', '--demangle', lib_path], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                symbols.extend(result.stdout.splitlines())
        except subprocess.TimeoutExpired:
            logging.warning("nm symbol extraction timed out")
    
    # 3. Извлечение информации о секциях
    try:
        result = subprocess.run(['readelf', '-S', lib_path], 
                              capture_output=True, text=True, timeout=20)
        if result.returncode == 0:
            symbols.extend([f"SECTION: {line}" for line in result.stdout.splitlines()[:20]])
    except subprocess.TimeoutExpired:
        logging.warning("readelf section extraction timed out")
    
    return symbols

def extract_string_references(lib_path):
    """Извлечение строковых ссылок из бинарного файла"""
    strings = []
    try:
        result = subprocess.run(['strings', '-a', lib_path], 
                              capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            strings = result.stdout.splitlines()
    except:
        pass
    
    # Фильтрация и анализ строк
    interesting_strings = []
    for s in strings:
        if len(s) > 4 and any(c in s for c in ['://', '/api/', '/v1/', 'http', 'https', 'lib', 'so']):
            interesting_strings.append(s)
    
    return interesting_strings

def analyze_vtables(symbols):
    """Анализ виртуальных таблиц на основе символов"""
    vtables = defaultdict(list)
    vtable_pattern = re.compile(r'vtable for (.*)')
    typeinfo_pattern = re.compile(r'typeinfo for (.*)')
    
    for line in symbols:
        # Поиск виртуальных таблиц
        vtable_match = vtable_pattern.search(line)
        if vtable_match:
            class_name = vtable_match.group(1)
            vtables[class_name].append(("vtable", line))
        
        # Поиск информации о типах
        typeinfo_match = typeinfo_pattern.search(line)
        if typeinfo_match:
            class_name = typeinfo_match.group(1)
            vtables[class_name].append(("typeinfo", line))
    
    return vtables

def parse_demangled_name(demangled_name):
    """Парсинг деманглированного имени для извлечения дополнительной информации"""
    result = {
        'class_name': '',
        'method_name': '',
        'return_type': '',
        'parameters': [],
        'is_const': False,
        'is_virtual': False,
        'is_static': False
    }
    
    # Попытка определить, является ли метод виртуальным
    if demangled_name.startswith('virtual '):
        result['is_virtual'] = True
        demangled_name = demangled_name[8:]
    
    # Попытка определить, является ли метод статическим
    if demangled_name.startswith('static '):
        result['is_static'] = True
        demangled_name = demangled_name[7:]
    
    # Попытка извлечения возвращаемого типа
    space_pos = demangled_name.find(' ')
    if space_pos != -1:
        result['return_type'] = demangled_name[:space_pos]
        demangled_name = demangled_name[space_pos+1:]
    
    # Попытка извлечения имени класса и метода
    if '::' in demangled_name:
        class_end = demangled_name.rfind('::')
        result['class_name'] = demangled_name[:class_end]
        method_part = demangled_name[class_end+2:]
        
        # Извлечение параметров
        paren_start = method_part.find('(')
        if paren_start != -1:
            result['method_name'] = method_part[:paren_start]
            params = method_part[paren_start+1:-1]  # Исключаем закрывающую скобку
            
            # Проверка на const метод
            if params.endswith(' const'):
                result['is_const'] = True
                params = params[:-6]
            
            # Разделение параметров
            if params:
                result['parameters'] = [p.strip() for p in params.split(',')]
        else:
            result['method_name'] = method_part
    
    return result

def parse_symbols_advanced(symbols):
    """Продвинутый парсинг символов с извлечением максимальной информации"""
    classes = defaultdict(list)
    functions = []
    variables = []
    vtables = analyze_vtables(symbols)
    
    # Основной паттерн для извлечения символов
    symbol_pattern = re.compile(
        r'^\s*\d+:\s+([0-9a-fA-F]{8,16})\s+\d+\s+(\w+)\s+(\w+)\s+\w+\s+\d+\s+(.+)'
    )
    
    for line in symbols:
        # Пропускаем строки без полезной информации
        if not line.strip() or 'SECTION:' in line:
            continue
            
        # Парсинг стандартных символов
        match = symbol_pattern.search(line)
        if match:
            offset, type_, bind, name = match.groups()
            
            # Пропускаем нулевые смещения
            if offset == "00000000" or offset == "0000000000000000":
                continue
                
            symbol_info = {
                'offset': offset,
                'type': type_,
                'bind': bind,
                'name': name,
                'demangled': '',
                'parsed': {}
            }
            
            # Попытка деманглации имени
            if name.startswith('_Z'):
                try:
                    result = subprocess.run(['c++filt', name], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        demangled_name = result.stdout.strip()
                        symbol_info['demangled'] = demangled_name
                        symbol_info['parsed'] = parse_demangled_name(demangled_name)
                        
                        # Добавление в классы, если это метод класса
                        if symbol_info['parsed']['class_name']:
                            class_name = symbol_info['parsed']['class_name']
                            method_info = (
                                symbol_info['parsed']['method_name'],
                                f"({', '.join(symbol_info['parsed']['parameters'])})",
                                offset,
                                symbol_info['parsed']['return_type'],
                                symbol_info['parsed']['is_const'],
                                symbol_info['parsed']['is_virtual'],
                                symbol_info['parsed']['is_static']
                            )
                            classes[class_name].append(method_info)
                except:
                    pass
            
            # Классификация символов
            if type_ == 'FUNC':
                functions.append(symbol_info)
            elif type_ == 'OBJECT':
                variables.append(symbol_info)
    
    return classes, functions, variables, vtables

def analyze_inheritance(vtables, classes):
    """Анализ отношений наследования на основе виртуальных таблиц"""
    inheritance = defaultdict(list)
    
    # Поиск отношений наследования через typeinfo
    for class_name, items in vtables.items():
        for item_type, line in items:
            if item_type == 'typeinfo':
                # Попытка найти базовые классы
                if 'for' in line and 'typeinfo name for' not in line:
                    parts = line.split()
                    if len(parts) > 3 and parts[-2] == 'for':
                        base_class = parts[-1]
                        inheritance[base_class].append(class_name)
    
    return inheritance

def generate_advanced_dump(lib_name, classes, functions, variables, vtables, inheritance, output_dir):
    """Генерация расширенного дампа с дополнительной информацией"""
    clean_lib_name = lib_name.replace('lib', '', 1) if lib_name.startswith('lib') else lib_name
    output_path = f"{output_dir}/{clean_lib_name}_advanced_dump"
    os.makedirs(output_path, exist_ok=True)
    
    # 1. Генерация основного файла с классами
    dump_file = os.path.join(output_path, f"{clean_lib_name}_classes.cpp")
    with open(dump_file, "w", encoding="utf-8") as out:
        out.write(f"// Advanced dump for {clean_lib_name}\n")
        out.write(f"// Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for cls in sorted(classes):
            # Определяем, есть ли виртуальная таблица для этого класса
            is_polymorphic = cls in vtables
            
            out.write(f"class {cls}")
            
            # Добавляем наследование, если известно
            if cls in inheritance:
                bases = inheritance[cls]
                if bases:
                    out.write(f" : public {', public '.join(bases)}")
            
            out.write(" {\n")
            
            if is_polymorphic:
                out.write("public:\n")
                out.write(f"    // Virtual table at 0x{vtables[cls][0][1].split()[0] if vtables[cls] else 'unknown'}\n")
            
            # Разделяем методы по типам
            constructors = []
            destructors = []
            methods = []
            static_methods = []
            
            for method in classes[cls]:
                method_name, params, offset, return_type, is_const, is_virtual, is_static = method
                
                if method_name == cls.split('::')[-1]:
                    constructors.append((method_name, params, offset, return_type))
                elif method_name == '~' + cls.split('::')[-1]:
                    destructors.append((method_name, params, offset, return_type))
                elif is_static:
                    static_methods.append((method_name, params, offset, return_type, is_const, is_virtual))
                else:
                    methods.append((method_name, params, offset, return_type, is_const, is_virtual))
            
            # Вывод конструкторов
            if constructors:
                out.write("public:\n")
                for method_name, params, offset, return_type in constructors:
                    out.write(f"    {cls}{params}; // offset: 0x{int(offset, 16):x}\n")
            
            # Вывод деструкторов
            if destructors:
                out.write("public:\n")
                for method_name, params, offset, return_type in destructors:
                    out.write(f"    virtual ~{cls.split('::')[-1]}(){params}; // offset: 0x{int(offset, 16):x}\n")
            
            # Вывод статических методов
            if static_methods:
                out.write("public:\n")
                for method_name, params, offset, return_type, is_const, is_virtual in static_methods:
                    out.write(f"    static {return_type} {method_name}{params}; // offset: 0x{int(offset, 16):x}\n")
            
            # Вывод обычных методов
            if methods:
                out.write("public:\n")
                for method_name, params, offset, return_type, is_const, is_virtual in methods:
                    const_suffix = " const" if is_const else ""
                    virtual_prefix = "virtual " if is_virtual else ""
                    out.write(f"    {virtual_prefix}{return_type} {method_name}{params}{const_suffix}; // offset: 0x{int(offset, 16):x}\n")
            
            out.write("};\n\n")
    
    # 2. Генерация файла с глобальными функцияи
    func_file = os.path.join(output_path, f"{clean_lib_name}_functions.cpp")
    with open(func_file, "w", encoding="utf-8") as out:
        out.write(f"// Global functions for {clean_lib_name}\n\n")
        for func in functions:
            if func['demangled']:
                out.write(f"// {func['demangled']}\n")
            out.write(f"// Offset: 0x{int(func['offset'], 16):x}, Type: {func['type']}, Bind: {func['bind']}\n")
            out.write(f"// Original name: {func['name']}\n\n")
    
    # 3. Генерация файла с глобальными переменными
    var_file = os.path.join(output_path, f"{clean_lib_name}_variables.cpp")
    with open(var_file, "w", encoding="utf-8") as out:
        out.write(f"// Global variables for {clean_lib_name}\n\n")
        for var in variables:
            if var['demangled']:
                out.write(f"// {var['demangled']}\n")
            out.write(f"// Offset: 0x{int(var['offset'], 16):x}, Type: {var['type']}, Bind: {var['bind']}\n")
            out.write(f"// Original name: {var['name']}\n\n")
    
    # 4. Генерация файла с виртуальными таблицами
    vtable_file = os.path.join(output_path, f"{clean_lib_name}_vtables.cpp")
    with open(vtable_file, "w", encoding="utf-8") as out:
        out.write(f"// Virtual tables for {clean_lib_name}\n\n")
        for cls, items in vtables.items():
            out.write(f"// VTable for {cls}\n")
            for item_type, line in items:
                out.write(f"// {line}\n")
            out.write("\n")
    
    return output_path

def main():
    """Основная функция скрипта"""
    parser = argparse.ArgumentParser(description='Advanced Radare2 Dumper')
    parser.add_argument('-i', '--input', help='Path to .so file for analysis')
    parser.add_argument('-o', '--output', default='./output', help='Output directory for results')
    parser.add_argument('--no-banner', action='store_true', help='Don\'t show banner')
    args = parser.parse_args()
    
    # Настройка логирования
    setup_logging()
    
    # Показ баннера
    if not args.no_banner:
        clear_screen()
        animated_banner()
    
    # Определение пути к библиотеке
    lib_path = args.input
    if not lib_path:
        so_files = get_so_files()
        if not so_files:
            logging.error(MESSAGES["no_so_files"])
            input(color(MESSAGES["press_enter"], "36"))
            sys.exit(1)
        lib_path = get_user_input(so_files)
    
    # Проверка валидности файла
    if not os.path.isfile(lib_path):
        logging.error(f"{MESSAGES['file_not_found']} {lib_path}")
        sys.exit(1)
    
    if not is_valid_elf(lib_path):
        logging.error(f"{MESSAGES['elf_check_failed']}: {lib_path}")
        sys.exit(1)
    
    # Определение архитектуры
    arch = detect_architecture(lib_path)
    logging.info(f"{MESSAGES['arch_detected']} {arch}")
    
    # Проверка окружения Termux
    if is_termux():
        logging.info(MESSAGES["termux_detected"])
        
        # Проверка разрешения хранилища
        storage_test = os.path.join(os.environ['HOME'], 'storage', 'shared')
        if not os.path.exists(storage_test):
            logging.warning(MESSAGES["storage_permission"])
            logging.warning(MESSAGES["grant_storage"])
        
        # Проверка и установка binutils
        if not check_command('readelf') or not check_command('c++filt'):
            logging.warning(MESSAGES["missing_binutils"])
            install_binutils_termux()
    
    # Извлечение и обработка символов
    start_time = time.time()
    
    logging.info(MESSAGES["extracting"])
    symbols = extract_symbols_advanced(lib_path)
    
    logging.info(MESSAGES["string_references"])
    strings = extract_string_references(lib_path)
    
    logging.info(MESSAGES["processing"])
    classes, functions, variables, vtables = parse_symbols_advanced(symbols)
    
    logging.info(MESSAGES["vtable_analysis"])
    inheritance = analyze_inheritance(vtables, classes)
    
    # Генерация результатов
    lib_name = os.path.splitext(os.path.basename(lib_path))[0]
    output_path = generate_advanced_dump(lib_name, classes, functions, variables, vtables, inheritance, args.output)
    
    # Вывод статистики
    method_count = sum(len(methods) for methods in classes.values())
    time_taken = time.time() - start_time
    
    logging.info(f"{MESSAGES['methods_found']} {method_count}")
    logging.info(f"{MESSAGES['classes_found']} {len(classes)}")
    logging.info(f"{MESSAGES['time_taken']} {time_taken:.2f}s")
    logging.info(f"Dump saved to: {output_path}")
    
    # Сохранение строковых ссылок
    if strings:
        strings_file = os.path.join(output_path, "string_references.txt")
        with open(strings_file, 'w', encoding='utf-8') as f:
            for s in strings:
                f.write(f"{s}\n")
        logging.info(f"String references saved to: {strings_file}")
    
    if not args.input:  # Если запущено в интерактивном режиме
        input(color(MESSAGES["press_enter"], "36"))

if __name__ == "__main__":
    main()