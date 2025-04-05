from bcc import BPF
import ctypes
import sys
import time
import configparser
import os
from enum import IntEnum
from datetime import datetime

CONFIG_FILE = './firewall.conf'
LOG_FILE = './firewall.log'

class TrafficType(IntEnum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    OTHER = 3

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls') #очистка экрана

def show_menu():           #главное меню
    clear_screen()
    print("╔══════════════════════════════════╗")
    print("║       Менеджер firewall'a        ║")
    print("╠══════════════════════════════════╣")
    print("║ 1. Показать текущие порты        ║")
    print("║ 2. Добавить разрешенные порты    ║")
    print("║ 3. Удалить разрешенные порты     ║")
    print("║ 4. Запустить фаервол             ║")
    print("║ 5. Просмотр логов                ║")
    print("║ 6. Выход                         ║")
    print("╚══════════════════════════════════╝")

def log_blocked_port(dest_port, src_port, protocol, reason):       #логирование блокировок портов
    log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - BLOCKED: dest_port={dest_port}, src_port={src_port}, protocol={protocol}, reason={reason}\n"
    
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Ошибка записи в лог: {e}")

def load_config():                    #загрузка настроек из файла конфигурации
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
    if not config.has_section('PORTS'):
        config['PORTS'] = {
            'default_ports': '80,443',
            'custom_ports': ''
        }
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            config.write(f)
    
    default_ports = [int(p.strip()) for p in config['PORTS']['default_ports'].split(',') if p.strip()]
    custom_ports = [int(p.strip()) for p in config['PORTS']['custom_ports'].split(',') if p.strip()]
    
    return default_ports, custom_ports

def update_ports(action, ports):                     #обновление списка портов
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
    if not config.has_section('PORTS'):
        config['PORTS'] = {'default_ports': '80,443', 'custom_ports': ''}
    
    current_ports = set()
    if config['PORTS']['custom_ports'].strip():
        current_ports = set(int(p.strip()) for p in config['PORTS']['custom_ports'].split(','))
    
    ports_to_modify = set(int(p.strip()) for p in ports if p.strip())
    
    if action == 'add':
        updated_ports = current_ports.union(ports_to_modify)
    elif action == 'del':
        updated_ports = current_ports - ports_to_modify
    
    config['PORTS']['custom_ports'] = ','.join(map(str, sorted(updated_ports)))
    
    with open(CONFIG_FILE, 'w') as f:
        config.write(f)
    
    return updated_ports

def show_ports():                       #показ текущих настроек портов
    default_ports, custom_ports = load_config()
    print("\nТекущие настройки портов:")
    print(" ┌──────────────────────────────────┐")
    print(f"│ Стандартные порты: {', '.join(map(str, default_ports)):15}")
    print(f"│ Пользовательские порты: {', '.join(map(str, custom_ports)):10}")
    print(f"│ Все разрешенные порты: {', '.join(map(str, set(default_ports + custom_ports))):12}")
    print(" └──────────────────────────────────┘")

def view_logs():                        #показ логов блокировок с файла
    try:
        with open(LOG_FILE, 'r') as f:
            logs = f.read()
            if logs:
                print("\nПоследние блокировки:")
                print("┌─────────────────────────────────────────────────────────────┐")
                for line in logs.split('\n')[-10:]:  #показ последних 10 записей с логов
                    if line:
                        print(f"│ {line:59} │")
                print("└─────────────────────────────────────────────────────────────┘")
            else:
                print("\nЛог файл пуст.")
    except FileNotFoundError:
        print("\nЛог файл не найден. Блокировок еще не было.")

def interactive_add_ports():                          #интерактивное добавление портов
    show_ports()
    ports = input("\nВведите порты для добавления (через запятую): ").strip()
    if ports:
        update_ports('add', ports.split(','))
        print(f"\nПорты {ports} успешно добавлены!")
        show_ports()
    else:
        print("\nНе введены порты для добавления.")
    input("\nНажмите Enter для продолжения...")

def interactive_remove_ports():                      #интерактивное удаление портов
    show_ports()
    ports = input("\nВведите порты для удаления (через запятую): ").strip()
    if ports:
        update_ports('del', ports.split(','))
        print(f"\nПорты {ports} успешно удалены!")
        show_ports()
    else:
        print("\nНе введены порты для удаления.")
    input("\nНажмите Enter для продолжения...")

def run_firewall():                         #запуск firewall
    interface = input("Введите интерфейс для защиты (по умолчанию lo): ").strip() or "lo"
    
    default_ports, custom_ports = load_config()
    allowed_ports = list(set(default_ports + custom_ports))
    
    b = BPF(text=BPF_PROGRAM)
    ports_table = b["allowed_ports"]
    
    #очистка таблицы перед загрузкой новых портов
    ports_table.clear()
    
    #загрузка разрешённых портов
    for port in allowed_ports:
        ports_table[ctypes.c_ushort(port)] = ctypes.c_ubyte(1)
    
    try:
        fn = b.load_func("block_port", BPF.XDP)
        b.attach_xdp(interface, fn, 0)
    except Exception as e:
        print(f"Ошибка: {e}")
        input("\nНажмите Enter для продолжения...")
        return

    print(f"\nFirewall запущен на интерфейсе {interface}")
    print(f"Разрешены входящие порты: {allowed_ports}")
    print("\nДля остановки нажмите Ctrl+C...")

    try:
        while True:
            try:
                (_, _, _, _, _, msg) = b.trace_fields()
                msg_str = msg.decode()
                print(msg_str)
                
                #логирование блокировок в терминал
                if "BLOCKED: Port" in msg_str:
                    port = msg_str.split()[-1]
                    log_blocked_port(port, "unknown", "TCP", "Incoming port not allowed")
                
            except ValueError:
                pass
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    
    b.remove_xdp(interface)
    print("\nFirewall остановлен")
    input("\nНажмите Enter для продолжения...")

def main_menu():               #г.меню управления firewall'ом
    while True:
        show_menu()
        choice = input("\nВыберите действие (1-6): ")
        
        if choice == '1':
            show_ports()
            input("\nНажмите Enter для продолжения...")
        elif choice == '2':
            interactive_add_ports()
        elif choice == '3':
            interactive_remove_ports()
        elif choice == '4':
            run_firewall()
        elif choice == '5':
            view_logs()
            input("\nНажмите Enter для продолжения...")
        elif choice == '6':
            print("\nВыход из программы...")
            break
        else:
            print("\nНеверный выбор. Попробуйте снова.")
            time.sleep(1)

BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bcc/proto.h>

BPF_HASH(allowed_ports, u16, u8);

//проверка HTTP сигнатуры
static int check_http(struct tcphdr *tcp, void *data_end) {
    //проверка первых несколько байт payload на HTTP методы
    char *payload = (char *)(tcp + 1);
    if ((void *)(payload + 7) > data_end)
        return 0;
    
    //проверка HTTP методов
    if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ')
        return 1;
    if (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T')
        return 1;
    if (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P')
        return 1;
    
    return 0;
}

//проверка TLS/HTTPS сигнатуры
static int check_https(struct tcphdr *tcp, void *data_end) {
    char *payload = (char *)(tcp + 1);
    if ((void *)(payload + 5) > data_end)
        return 0;
    
    //проверка на TLS handshake
    if (payload[0] == 0x16 && payload[1] == 0x03) {
        // TLS версия 1.0-1.3
        if (payload[2] >= 0x01 && payload[2] <= 0x04)
            return 1;
    }
    
    return 0;
}

int block_port(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    //только IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    //только TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    u16 dest_port = bpf_ntohs(tcp->dest);
    u16 src_port = bpf_ntohs(tcp->source);

    //простая проверка на входящий трафик (SYN-пакет без ACK)
    if (tcp->syn && !tcp->ack) {
        u8 *allowed = allowed_ports.lookup(&dest_port);
        if (!allowed) {
            bpf_trace_printk("BLOCKED: Port %d\\n", dest_port);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}
"""

def main():           #стандартные команды консоли
    if len(sys.argv) > 1:
        if sys.argv[1] == '--add':
            if len(sys.argv) < 3:
                print("Ошибка: укажите порты через запятую")
                sys.exit(1)
            update_ports('add', sys.argv[2].split(','))
            print(f"Добавлены порты: {sys.argv[2]}")
            show_ports()
            return
        elif sys.argv[1] == '--del':
            if len(sys.argv) < 3:
                print("Ошибка: укажите порты через запятую")
                sys.exit(1)
            update_ports('del', sys.argv[2].split(','))
            print(f"Удалены порты: {sys.argv[2]}")
            show_ports()
            return
        elif sys.argv[1] == '--list':
            show_ports()
            return
        elif sys.argv[1] == '--help':
            print_help()
            return
    
    default_ports, custom_ports = load_config()
    allowed_ports = list(set(default_ports + custom_ports))
    
    b = BPF(text=BPF_PROGRAM)
    ports_table = b["allowed_ports"]
    
    # очистка таблицы
    ports_table.clear()
    
    #загрузка разрешенных портов
    for port in allowed_ports:
        ports_table[ctypes.c_ushort(port)] = ctypes.c_ubyte(1)
        print(f"Allowed port: {port}") 
    
    interface = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('--') else "lo"
    
    try:
        fn = b.load_func("block_port", BPF.XDP)
        b.attach_xdp(interface, fn, 0)
    except Exception as e:
        print(f"Ошибка: {e}")
        return
    
    
    print(f"Запущен фаервол на {interface}. Разрешены входящие порты: {allowed_ports}")
    print("Нажмите Ctrl+C для остановки...")

    try:
        while True:
            try:
                (_, _, _, _, _, msg) = b.trace_fields()
                msg_str = msg.decode()
                print(msg_str)
                
                #анализ сообщений о блокировке для логирования
                if "Blocked incoming port:" in msg_str:
                    port = msg_str.split()[-1]
                    log_blocked_port(port, "unknown", "TCP", "Incoming port not allowed")
                
                elif "Blocked non-HTTP" in msg_str:
                    port = msg_str.split()[-1]
                    log_blocked_port(port, "unknown", "HTTP", "Non-HTTP traffic on HTTP port")
                
                elif "Blocked non-HTTPS" in msg_str:
                    port = msg_str.split()[-1]
                    log_blocked_port(port, "unknown", "HTTPS", "Non-HTTPS traffic on HTTPS port")
                
            except ValueError:
                pass
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    
    b.remove_xdp(interface)
    print("\nFirewall остановлен")

def print_help():  #sudo ./firewall.py -h
    print("Использование:")
    print("  Запуск firewall'a: sudo ./firewall.py [интерфейс(например:lo,wlan3,enp0s3,...)]")
    print("  Добавить порты:  sudo ./firewall.py --add порт1,порт2,...")
    print("  Удалить порты:   sudo ./firewall.py --del порт1,порт2,...")
    print("  Список портов:   sudo ./firewall.py --list")
    print("  Помощь:          sudo ./firewall.py --help")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        #режим командной строки для совместимости
        if sys.argv[1] == '--add':
            if len(sys.argv) < 3:
                print("Ошибка: укажите порты через запятую")
                sys.exit(1)
            update_ports('add', sys.argv[2].split(','))
            print(f"Добавлены порты: {sys.argv[2]}")
            show_ports()
        elif sys.argv[1] == '--del':
            if len(sys.argv) < 3:
                print("Ошибка: укажите порты через запятую")
                sys.exit(1)
            update_ports('del', sys.argv[2].split(','))
            print(f"Удалены порты: {sys.argv[2]}")
            show_ports()
        elif sys.argv[1] == '--list':
            show_ports()
        elif sys.argv[1] == '--run':
            run_firewall()
        elif sys.argv[1] in ['--help', '-h']:
            print_help()
    else:
        #запуск главного меню
        main_menu()
