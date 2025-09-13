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
    "export_html": "Exporting HTML report:"
}

def clear_screen():
    """Очистка экрана терминала"""
    os.system('cls' if os.name == 'nt' else 'clear')

def animated_banner():
    """Анимированный баннер с проверкой размера терминала"""
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
                              capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'Machine:' in line:
                    return line.split(':')[1].strip()
    except:
        pass
    return "Unknown"

def get_cache_path(file_path):
    """Генерация пути для кэширования на основе хеша файла"""
    file_hash = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            file_hash.update(chunk)
    return f".cache/{file_hash.hexdigest()}_symbols.txt"

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

def extract_symbols(lib_path, use_cache=True):
    """Извлечение символов из библиотеки с поддержкой кэширования"""
    cache_path = get_cache_path(lib_path)
    
    # Проверка кэша
    if use_cache and os.path.exists(cache_path):
        logging.info(f"{MESSAGES['cache_used']} {cache_path}")
        with open(cache_path, 'r', encoding='utf-8') as f:
            return f.read().splitlines()
    
    # Извлечение символов
    logging.info(f"{MESSAGES['extracting']} {lib_path}")
    try:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        
        with open(cache_path, 'w', encoding='utf-8') as cache_file:
            p1 = subprocess.Popen(['readelf', '-Ws', lib_path], stdout=subprocess.PIPE)
            p2 = subprocess.Popen(['c++filt'], stdin=p1.stdout, stdout=cache_file)
            p1.stdout.close()
            p2.communicate()
        
        with open(cache_path, 'r', encoding='utf-8') as f:
            return f.read().splitlines()
            
    except Exception as e:
        logging.error(f"Symbol extraction failed: {str(e)}")
        if os.path.exists(cache_path):
            os.remove(cache_path)
        sys.exit(1)

def parse_symbols_parallel(symbols, max_workers=4):
    """Многопоточный парсинг символов"""
    classes = defaultdict(list)
    pattern = re.compile(
        r'^\s*\d+:\s+([0-9a-fA-F]{8,16})\s+\d+\s+(?:FUNC|OBJECT)\s+(?:GLOBAL|WEAK).*?\s+'
        r'((?:[a-zA-Z0-9_]+::)*[a-zA-Z0-9_~]+(?:<[^>]+>)?::[a-zA-Z0-9_~]+\([^)]*\))'
    )
    
    def process_line(line):
        match = pattern.search(line)
        if match:
            offset, full_name = match.groups()
            if offset == "00000000" or offset == "0000000000000000":
                return None
            if "::" in full_name:
                try:
                    class_path, method_with_params = full_name.rsplit("::", 1)
                    method_name = method_with_params.split('(')[0]
                    params = method_with_params[len(method_name):]
                    return (class_path, method_name, params, offset)
                except:
                    pass
        return None
    
    # Многопоточная обработка
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_line, line) for line in symbols]
        
        for future in tqdm(as_completed(futures), total=len(symbols), 
                          desc="Processing symbols", unit="symbol"):
            result = future.result()
            if result:
                class_path, method_name, params, offset = result
                classes[class_path].append((method_name, params, offset))
    
    return classes

def generate_dump(lib_name, classes, output_dir, output_formats=None):
    """Генерация дампа в различных форматах"""
    if output_formats is None:
        output_formats = ['cpp', 'json', 'html']
    
    clean_lib_name = lib_name.replace('lib', '', 1) if lib_name.startswith('lib') else lib_name
    output_path = f"{output_dir}/{clean_lib_name}@dump"
    os.makedirs(output_path, exist_ok=True)
    logging.info(f"{MESSAGES['output_dir_created']} {output_path}")
    
    # Генерация CPP дампа
    if 'cpp' in output_formats:
        dump_file = os.path.join(output_path, f"{clean_lib_name}.cpp")
        with open(dump_file, "w", encoding="utf-8") as out:
            for cls in sorted(classes):
                out.write(f"class {cls} {{\n")
                for method_name, params, offset in sorted(set(classes[cls])):
                    formatted_offset = f"0x{int(offset, 16):x}"
                    out.write(f"      {method_name}{params}; //{formatted_offset}\n")
                out.write("};\n\n")
    
    # Генерация JSON метаданных
    if 'json' in output_formats:
        json_file = os.path.join(output_path, f"{clean_lib_name}_metadata.json")
        logging.info(f"{MESSAGES['export_json']} {json_file}")
        
        metadata = {
            "library": clean_lib_name,
            "classes": [],
            "total_methods": 0,
            "timestamp": time.time()
        }
        
        for cls, methods in classes.items():
            class_info = {
                "name": cls,
                "methods": [],
                "method_count": len(methods)
            }
            
            for method_name, params, offset in methods:
                class_info["methods"].append({
                    "name": method_name,
                    "params": params,
                    "offset": f"0x{int(offset, 16):x}"
                })
            
            metadata["classes"].append(class_info)
            metadata["total_methods"] += len(methods)
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
    
    # Генерация HTML отчета
    if 'html' in output_formats:
        html_file = os.path.join(output_path, f"{clean_lib_name}_report.html")
        logging.info(f"{MESSAGES['export_html']} {html_file}")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Radare2 Dumper Report - {clean_lib_name}</title>
            <style>
                body {{ font-family: monospace; margin: 20px; }}
                .class {{ margin-bottom: 20px; border: 1px solid #ccc; padding: 10px; }}
                .method {{ margin-left: 20px; }}
                .offset {{ color: #888; }}
            </style>
        </head>
        <body>
            <h1>Radare2 Dumper Report</h1>
            <p>Library: <b>{clean_lib_name}</b></p>
            <p>Classes: {len(classes)}</p>
            <p>Total methods: {sum(len(methods) for methods in classes.values())}</p>
            <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <hr>
        """
        
        for cls in sorted(classes):
            html_content += f'<div class="class"><h2>class {cls}</h2>\n'
            for method_name, params, offset in sorted(set(classes[cls])):
                formatted_offset = f"0x{int(offset, 16):x}"
                html_content += f'<div class="method">{method_name}{params}; <span class="offset">//{formatted_offset}</span></div>\n'
            html_content += '</div>\n'
        
        html_content += "</body></html>"
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    return output_path

def main():
    """Основная функция скрипта"""
    # Парсинг аргументов командной строки
    parser = argparse.ArgumentParser(description='Radare2 Dumper - инструмент для анализа библиотек')
    parser.add_argument('-i', '--input', help='Путь к .so файлу для анализа')
    parser.add_argument('-o', '--output', default='./output', help='Директория для сохранения результатов')
    parser.add_argument('-f', '--format', choices=['cpp', 'json', 'html', 'all'], 
                       default='cpp', help='Формат вывода (по умолчанию: cpp)')
    parser.add_argument('--no-cache', action='store_true', help='Не использовать кэширование')
    parser.add_argument('--no-banner', action='store_true', help='Не показывать баннер')
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
    symbols = extract_symbols(lib_path, use_cache=not args.no_cache)
    classes = parse_symbols_parallel(symbols)
    
    # Определение форматов вывода
    output_formats = ['cpp']
    if args.format == 'all':
        output_formats = ['cpp', 'json', 'html']
    elif args.format != 'cpp':
        output_formats = [args.format]
    
    # Генерация результатов
    lib_name = os.path.splitext(os.path.basename(lib_path))[0]
    output_path = generate_dump(lib_name, classes, args.output, output_formats)
    
    # Вывод статистики
    method_count = sum(len(methods) for methods in classes.values())
    time_taken = time.time() - start_time
    
    logging.info(f"{MESSAGES['methods_found']} {method_count}")
    logging.info(f"{MESSAGES['classes_found']} {len(classes)}")
    logging.info(f"{MESSAGES['saved_to']} {output_path}")
    logging.info(f"{MESSAGES['time_taken']} {time_taken:.2f}s")
    
    if not args.input:  # Если запущено в интерактивном режиме
        input(color(MESSAGES["press_enter"], "36"))

if __name__ == "__main__":
    main()