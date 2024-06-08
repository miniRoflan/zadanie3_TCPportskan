import socket
from multiprocessing import Pool
from argparse import ArgumentParser


def main():
    parser = ArgumentParser(description='UDP and TCP ports scanner')  # Добавляем поддержку обработки ключей из консоли
    parser.add_argument('destination', type=str, help='Destination IPv4 or name')  # тут и далее иформация в поле help
    parser.add_argument('-s', '--start_port', default=1, type=int, help='Start port to scan')
    parser.add_argument('-e', '--end_port', default=150, type=int, help='End port to scan')
    parser.add_argument('-t', '--timeout', default=100, type=int, help='Timeout of response in milliseconds')
    parser.add_argument('-tcp', action='store_true', help='Scan TCP ports')
    parser.add_argument('-udp', action='store_true', help='Scan UDP ports')
    parser.add_argument('-p', '--processes', default=4, type=int, help='Count of processes to scan')
    args = parser.parse_args()
    if not args.tcp and not args.udp:  # если пользователь не ввел соответствующие ключи - сканируем и tcp и udp порты
        args.tcp = args.udp = True
    scanner = PortScanner(args.destination,
                          args.timeout)  # инициализируем наш сканер с указанной целью и временем ожидания отклика
    pool = Pool(args.processes)  # Распараллелим все (По умолчанию выделяется 4 процесса)
    if args.tcp:
        scan = pool.imap(scanner.TCP_connect, range(args.start_port, args.end_port + 1))  # отправляем задачу
        # процессам просканировать указанные порты. Для этого переместимся в функцию scan_tcp_port
        for port, protocol in scan:  # выводим открытые TCP порты, вместе с протоклами по которым мы их обнаружили
            if protocol:
                print(f'TCP port {port} is open. Protocol: {protocol}')
    if args.udp:
        scan = pool.imap(scanner.scan_udp_port, range(args.start_port, args.end_port + 1))  # абсолютно то же с UDP,
        # но функция scan_udp_port
        for port, protocol in scan:
            if protocol:
                print(f'UDP port {port} is open. Protocol: {protocol}')


class PortScanner:
    DNS_TRANSACTION_ID = b'\x00\x00'

    DNS_PACKET = DNS_TRANSACTION_ID + \
                 b'\x01\x00\x00\x01' + \
                 b'\x00\x00\x00\x00\x00\x00' + \
                 b'\x02\x65\x31\x02\x72\x75' + \
                 b'\x00\x00\x01\x00\x01'  # формируем DNS пакет для запроса на сервер

    UDP_PACKETS = {
        'DNS': DNS_PACKET
    }

    PROTOCOL_CHECKER = {
        'HTTP': lambda packet: b'HTTP' in packet,
        'DNS': lambda packet: packet.startswith(PortScanner.DNS_TRANSACTION_ID),
    }

    def __init__(self, dest, timeout):
        self.dest = dest
        self.timeout = timeout / 1000

    def TCP_connect(self, port_number):
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.settimeout(self.timeout)
        try:
            tcp_sock.connect((self.dest, port_number))
            return port_number, "_"
        except socket.error:
            pass
        return None, None

    def scan_udp_port(self, port):
        socket.setdefaulttimeout(self.timeout)  # Устанавливаем время ожидания
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:  # Создаем UDP сокет
            for protocol, packet in PortScanner.UDP_PACKETS.items():  # Для каждого протокола
                s.sendto(packet, (self.dest, port))  # отправляем дату
                try:
                    if PortScanner.PROTOCOL_CHECKER[protocol](s.recv(128)):  # смотрим совпадает ли ответный пакет с
                        # нашим для DNS
                        return port, protocol  # если все в порядке, то говорим что порт открыт
                except socket.error:
                    continue
        return port, None


if __name__ == "__main__":
    main()