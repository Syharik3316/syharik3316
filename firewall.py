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
    os.system('clear' if os.name == 'posix' else 'cls')

def show_menu():
    clear_screen()
    print("╔══════════════════════════════════╗")
    print("║  Менеджер firewall'a by syharik  ║")
    print("╠══════════════════════════════════╣")
    print("║ 1. Показать текущие настройки    ║")
    print("║ 2. Доб. разрешенные порты        ║")
    print("║ 3. Убр. разрешенные порты        ║")
    print("║ 4. Запустить firewall            ║")
    print("║ 5. Просмотр логов                ║")
    print("║ 6. Дополнительные настройки      ║")
    print("║ 7. Выход                         ║")
    print("╚══════════════════════════════════╝")

def log_event(event_type, dest_port, src_port, protocol, reason):
    log_entry = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {event_type}: dest_port={dest_port}, src_port={src_port}, protocol={protocol}, reason={reason}\n"
    
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Ошибка логирования: {e}")

def load_config():
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
    if not config.has_section('SETTINGS'):
        config['SETTINGS'] = {
            'strict_mode': '1',
            'allow_dns': '1',
            'allow_icmp': '0'
        }
    
    if not config.has_section('PORTS'):
        config['PORTS'] = {
            'default_ports': '80,443',
            'custom_ports': ''
        }
        with open(CONFIG_FILE, 'w') as f:
            config.write(f)
    
    default_ports = [int(p.strip()) for p in config['PORTS']['default_ports'].split(',') if p.strip()]
    custom_ports = [int(p.strip()) for p in config['PORTS']['custom_ports'].split(',') if p.strip()]
    
    strict_mode = config['SETTINGS'].getboolean('strict_mode', True)
    allow_dns = config['SETTINGS'].getboolean('allow_dns', True)
    allow_icmp = config['SETTINGS'].getboolean('allow_icmp', False)
    
    return default_ports, custom_ports, strict_mode, allow_dns, allow_icmp

def update_config(setting, value):
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    
    if not config.has_section('SETTINGS'):
        config['SETTINGS'] = {}
    
    config['SETTINGS'][setting] = str(value)
    
    with open(CONFIG_FILE, 'w') as f:
        config.write(f)

def update_ports(action, ports):
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

def show_settings():
    default_ports, custom_ports, strict_mode, allow_dns, allow_icmp = load_config()
    print("\nТекущие настройки firewall'a:")
    print(" ┌──────────────────────────────────┐")
    print(f"│ Всё кроме L7: {'Включено' if strict_mode else 'Отключено':<18}")
    print(f"│ Разрешить DNS: {'Да' if allow_dns else 'Нет':<24}")
    print(f"│ Разрешить ICMP: {'Да' if allow_icmp else 'Нет':<23}")
    print(f"│ Стандартные порты: {', '.join(map(str, default_ports)):15}")
    print(f"│ Пользовательские порты: {', '.join(map(str, custom_ports)):16}")
    print(f"│ Разрешеныне порты: {', '.join(map(str, set(default_ports + custom_ports))):14}")
    print(" └──────────────────────────────────┘")

def view_logs():
    try:
        with open(LOG_FILE, 'r') as f:
            logs = f.read()
            if logs:
                print("\nНедавние блокировки:")
                print("┌─────────────────────────────────────────────────────────────┐")
                for line in logs.split('\n')[-10:]:
                    if line:
                        print(f"│ {line:59} │")
                print("└─────────────────────────────────────────────────────────────┘")
            else:
                print("\nФайл блокировок пуст.")
    except FileNotFoundError:
        print("\nФайл не найден. Блокировок ещё не происходило.")

def interactive_add_ports():
    show_settings()
    ports = input("\nВведите порты для добавления(через запятую): ").strip()
    if ports:
        update_ports('add', ports.split(','))
        print(f"\nПорты {ports} успешно добавлены!")
        show_settings()
    else:
        print("\nПорты не были введены.")
    input("\nНажмите Enter для продолжения...")

def interactive_remove_ports():
    show_settings()
    ports = input("\nВведите какие порты нужно убрать (через запятую): ").strip()
    if ports:
        update_ports('del', ports.split(','))
        print(f"\nПорты {ports} успешно удалены!")
        show_settings()
    else:
        print("\nПорт не был введен.")
    input("\nPНажмите Enter для продолжения...")

def toggle_setting(setting_name, current_value):
    new_value = not current_value
    update_config(setting_name, new_value)
    print(f"\n{setting_name.replace('_', ' ').title()} set to {'Включено' if new_value else 'Выключено'}")
    return new_value

def advanced_settings():
    _, _, strict_mode, allow_dns, allow_icmp = load_config()
    
    while True:
        clear_screen()
        print(" ╔══════════════════════════════════╗")
        print(" ║     Дополнительные настройки     ║")
        print(" ╠══════════════════════════════════╣")
        print(f"   1. Всё кроме L7: {'✔' if strict_mode else '✖'}")
        print(f"   2. Разрешено DNS: {'✔' if allow_dns else '✖'}")
        print(f"   3. Разрешено ICMP: {'✔' if allow_icmp else '✖'}")
        print(" ║ 4. Назад в главное меню          ║")
        print(" ╚══════════════════════════════════╝")
        
        choice = input("\nSВыбор настройки (1-4): ")
        
        if choice == '1':
            strict_mode = toggle_setting('strict_mode', strict_mode)
        elif choice == '2':
            allow_dns = toggle_setting('allow_dns', allow_dns)
        elif choice == '3':
            allow_icmp = toggle_setting('allow_icmp', allow_icmp)
        elif choice == '4':
            break
        else:
            print("\nНеверный выбор.")
            time.sleep(1)

def run_firewall():
    interface = input("Введите интерфейс который нужно защитить (стандартно: lo): ").strip() or "lo"
    
    default_ports, custom_ports, strict_mode, allow_dns, allow_icmp = load_config()
    allowed_ports = list(set(default_ports + custom_ports))
    
    # Generate BPF program based on settings
    bpf_text = BPF_TEMPLATE.replace('//STRICT_MODE', '1' if strict_mode else '0')
    bpf_text = bpf_text.replace('//ALLOW_DNS', '1' if allow_dns else '0')
    bpf_text = bpf_text.replace('//ALLOW_ICMP', '1' if allow_icmp else '0')
    
    b = BPF(text=bpf_text)
    ports_table = b["allowed_ports"]
    
    ports_table.clear()
    
    for port in allowed_ports:
        ports_table[ctypes.c_ushort(port)] = ctypes.c_ubyte(1)
    
    try:
        fn = b.load_func("filter_traffic", BPF.XDP)
        b.attach_xdp(interface, fn, 0)
    except Exception as e:
        print(f"Error: {e}")
        input("\nНажмите Enter для продолжения...")
        return

    print(f"\nFirewall включен на {interface}")
    print(f"Разрешенные порты: {allowed_ports}")
    print(f"Всё кроме L7: {'Включено' if strict_mode else 'Отключено'}")
    print(f"DNS разрешен: {'Да' if allow_dns else 'Нет'}")
    print(f"ICMP разрешен: {'Да' if allow_icmp else 'Нет'}")
    print("\nНажмите Ctrl+C для остановки...")

    try:
        while True:
            try:
                (_, _, _, _, _, msg) = b.trace_fields()
                msg_str = msg.decode()
                print(msg_str)
                
                if "BLOCKED:" in msg_str:
                    parts = msg_str.split()
                    port = parts[3] if len(parts) > 3 else "unknown"
                    protocol = parts[5] if len(parts) > 5 else "unknown"
                    reason = " ".join(parts[7:]) if len(parts) > 7 else "unknown"
                    log_event("BLOCKED", port, "unknown", protocol, reason)
                
            except ValueError:
                pass
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    
    b.remove_xdp(interface)
    print("\nFirewall остановлен")
    input("\nНажмите Enter для продолжения...")

BPF_TEMPLATE = """
#include <uapi/linux/ptrace.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bcc/proto.h>

BPF_HASH(allowed_ports, u16, u8);

enum traffic_type {
    TRAFFIC_UNKNOWN = 0,
    TRAFFIC_HTTP = 1,
    TRAFFIC_HTTPS = 2,
    TRAFFIC_DNS = 3,
    TRAFFIC_ICMP = 4,
    TRAFFIC_OTHER = 5
};

// Check for HTTP traffic
static int is_http(struct tcphdr *tcp, void *data_end) {
    if (tcp->syn || tcp->fin || tcp->rst) return 0;
    if (!tcp->psh) return 0;  // No payload data
    
    char *payload = (char *)(tcp + 1);
    if ((void *)(payload + 8) > data_end) return 0;
    
    // Check for HTTP methods
    if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ') return 1;
    if (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T') return 1;
    if (payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D') return 1;
    if (payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T' && payload[3] == ' ') return 1;
    if (payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E') return 1;
    
    if (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P') return 1;
    
    return 0;
}

static int is_https(struct tcphdr *tcp, void *data_end) {
    if (tcp->syn || tcp->fin || tcp->rst) return 0;
    
    char *payload = (char *)(tcp + 1);
    if ((void *)(payload + 5) > data_end) return 0;
    
    if (payload[0] == 0x16 && payload[1] == 0x03) {
        // TLS versions 1.0-1.3
        if (payload[2] >= 0x01 && payload[2] <= 0x04) return 1;
    }
    
    return 0;
}

static int is_dns(struct udphdr *udp, void *data_end) {
    char *payload = (char *)(udp + 1);
    if ((void *)(payload + 12) > data_end) return 0;
    
    return 1;
}

int filter_traffic(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_ICMP) {
        if (//ALLOW_ICMP) {
            return XDP_PASS;
        } else {
            bpf_trace_printk("BLOCKED: ICMP protocol not allowed\\n");
            return XDP_DROP;
        }
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        u16 dest_port = bpf_ntohs(tcp->dest);
        u16 src_port = bpf_ntohs(tcp->source);

        u8 *allowed = allowed_ports.lookup(&dest_port);
        if (!allowed && !allowed_ports.lookup(&src_port)) {
            bpf_trace_printk("BLOCKED: Port %d not in allowed list\\n", dest_port);
            return XDP_DROP;
        }

        if (//STRICT_MODE) {
            if (dest_port == 80 || src_port == 80) {
                if (!is_http(tcp, data_end)) {
                    bpf_trace_printk("BLOCKED: Non-HTTP traffic on port 80\\n");
                    return XDP_DROP;
                }
            }
            else if (dest_port == 443 || src_port == 443) {
                if (!is_https(tcp, data_end)) {
                    bpf_trace_printk("BLOCKED: Non-HTTPS traffic on port 443\\n");
                    return XDP_DROP;
                }
            }
        }

        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        u16 dest_port = bpf_ntohs(udp->dest);
        u16 src_port = bpf_ntohs(udp->source);

        if (//ALLOW_DNS && (dest_port == 53 || src_port == 53)) {
            if (is_dns(udp, data_end)) {
                return XDP_PASS;
            }
        }

        bpf_trace_printk("BLOCKED: UDP traffic on port %d\\n", dest_port);
        return XDP_DROP;
    }

    bpf_trace_printk("BLOCKED: Non-TCP/UDP/ICMP protocol\\n");
    return XDP_DROP;
}
"""

def main_menu():
    while True:
        show_menu()
        choice = input("\nВыберите действие (1-7): ")
        
        if choice == '1':
            show_settings()
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
            advanced_settings()
        elif choice == '7':
            print("\nВыход из программы...")
            break
        else:
            print("\nНеверный выбор. Попробуйте снова.")
            time.sleep(1)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == '--add':
            if len(sys.argv) < 3:
                print("Error: Введите порты через запятую")
                sys.exit(1)
            update_ports('add', sys.argv[2].split(','))
            print(f"Добавлены порты: {sys.argv[2]}")
            show_settings()
        elif sys.argv[1] == '--del':
            if len(sys.argv) < 3:
                print("Error: Введите порты через запятую")
                sys.exit(1)
            update_ports('del', sys.argv[2].split(','))
            print(f"Удалены порты: {sys.argv[2]}")
            show_settings()
        elif sys.argv[1] == '--list':
            show_settings()
        elif sys.argv[1] == '--run':
            run_firewall()
        elif sys.argv[1] in ['--help', '-h']:
            print("Использование:")
            print("  Активация firewall: sudo ./firewall.py [interface]")
            print("  Добавление портов: sudo ./firewall.py --add port1,port2,...")
            print("  Удаление портов: sudo ./firewall.py --del port1,port2,...")
            print("  Показ настроек: sudo ./firewall.py --list")
            print("  Помощь: sudo ./firewall.py --help")
    else:
        main_menu()
