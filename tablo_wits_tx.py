import datetime
import socket
import threading
import time
import ctypes
import psutil


class MemoryReader:
    def __init__(self, process_name, bottomhole_address, pressure_address, bit_position_address):
        self.process_name = process_name
        self.bottomhole_address = bottomhole_address
        self.pressure_address = pressure_address
        self.bit_depth_address = bit_position_address
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.OpenProcess = self.kernel32.OpenProcess
        self.ReadProcessMemory = self.kernel32.ReadProcessMemory
        self.CloseHandle = self.kernel32.CloseHandle
        self.PROCESS_QUERY_INFORMATION = 0x0400
        self.PROCESS_VM_READ = 0x0010
        self.process_handle = None

    def open_process(self):
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == self.process_name:
                pid = proc.info['pid']
                self.process_handle = self.OpenProcess(self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ, False,
                                                       pid)
                if not self.process_handle:
                    raise Exception("Не удалось открыть процесс")
                return
        raise RuntimeError(f"Процесс {self.process_name} не найден")

    def read_float(self, address):
        buffer = ctypes.c_float()
        bytes_read = ctypes.c_size_t(0)
        success = self.ReadProcessMemory(self.process_handle, address, ctypes.byref(buffer), ctypes.sizeof(buffer),
                                         ctypes.byref(bytes_read))
        if not success or bytes_read.value != ctypes.sizeof(buffer):
            raise Exception("Ошибка чтения памяти")
        return buffer.value

    def close_process(self):
        if self.process_handle:
            self.CloseHandle(self.process_handle)
            self.process_handle = None


class WitsTx:
    def __init__(self, host='0.0.0.0', port=5021, memory_reader=None):
        self.host = host
        self.port = port
        self.params = {
            '0101': 'ALGIS',
            '0105': '',
            '0106': '',
            '0108': '',  # Забой
            '0110': '',  # Давление
            '0121': '',  # Положение долота
        }
        self.server_socket = None
        self.wits0_data = None
        self.clients = []
        self.clients_lock = threading.Lock()
        self.memory_reader = memory_reader  # Экземпляр класса MemoryReader

    def update_time(self):
        now = datetime.datetime.now()
        self.params['0105'] = now.strftime('%y%m%d')
        self.params['0106'] = now.strftime('%H%M%S')

    def form_wits0_data(self):
        self.update_time()
        if self.memory_reader:
            try:
                self.params['0108'] = str(
                    round(self.memory_reader.read_float(self.memory_reader.bottomhole_address), 2))
                self.params['0110'] = str(round(self.memory_reader.read_float(self.memory_reader.bit_depth_address), 2))
                self.params['0121'] = str(
                    round(self.memory_reader.read_float(self.memory_reader.pressure_address), 2))
            except Exception as e:
                print(f"Ошибка чтения из памяти: {e}")
        data = ['&&']
        for param_id, value in self.params.items():
            param_str = f'{param_id}{value}'
            data.append(param_str)
        data.append('!!')
        wits0_data = '\r\n'.join(data) + '\r\n\r\n'
        return wits0_data.encode('utf-8')

    def send_data_to_clients(self):
        while True:
            self.wits0_data = self.form_wits0_data()
            print(self.wits0_data.decode('utf-8'))
            with self.clients_lock:
                for client in self.clients[:]:
                    try:
                        client.sendall(self.wits0_data)
                    except Exception as e:
                        print(f"Ошибка при отправке данных клиенту: {e}")
                        self.clients.remove(client)
            time.sleep(1)

    def handle_client(self, conn, addr):
        with self.clients_lock:
            self.clients.append(conn)
        print(f"Подключение от {addr}")

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Сервер запущен на {self.host}:{self.port}")

        data_thread = threading.Thread(target=self.send_data_to_clients)
        data_thread.daemon = True
        data_thread.start()

        while True:
            try:
                conn, addr = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Ошибка при приеме подключения: {e}")


if __name__ == '__main__':
    try:
        # Настройки для чтения из памяти
        process_name = "Tablo.exe"
        bottomhole_address = 0x005E659C
        pressure_address = 0x005E6590
        bit_position_address = 0x005E65B8

        # Создание экземпляра MemoryReader
        memory_reader = MemoryReader(process_name, bottomhole_address, pressure_address, bit_position_address)
        memory_reader.open_process()  # Открытие процесса

        # Создание экземпляра WitsTx с передачей MemoryReader
        wits = WitsTx(memory_reader=memory_reader)
        wits.start()

    except Exception as e:
        print(f"Произошла ошибка: {e}")
    finally:
        if 'memory_reader' in locals():
            memory_reader.close_process()  # Закрытие процесса в любом случае

