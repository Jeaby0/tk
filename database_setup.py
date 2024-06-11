import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

def init_db():
    conn = sqlite3.connect('tickets.db')
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        show_info_window INTEGER NOT NULL DEFAULT 1
    )''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        title TEXT NOT NULL, 
        description TEXT NOT NULL,
        status TEXT DEFAULT 'Open',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    conn.commit()
    conn.close()

def create_user(username, password, role):
    conn = sqlite3.connect('tickets.db')
    cursor = conn.cursor()
    hashed_password = generate_password_hash(password)
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
    conn.commit()
    conn.close()

init_db()
# Ejemplo para crear un usuario admin
create_user('admin', 'admin123', 'admin')
create_user("yazmin ortiz", "abc", "Administracion")
create_user("gabriel valle", "def", "Laboratorio")
create_user("michelle rosales", "ghi", "Administracion")
create_user("victor quiroz", "jkl", "Compras")
create_user("andrea rosales", "mno", "Produccion")
create_user("rafael ramos", "pqr", "Administracion")
create_user("israel", "stu", "Produccion")
create_user("rosy barron", "vwx", "Produccion")
create_user("carlos liao", "yz1", "Compras")
create_user("pamela lomeli", "234", "Muestras")
create_user("meiquin", "567", "Muestras")
create_user("maria murillo", "890", "Sales")
create_user("yuritzy", "abc", "Almacen General")
create_user("martin", "def", "Almacen General")
create_user("maria villanueva", "ghi", "Almacen General")
create_user("wing", "jkl", "Calcetines")
create_user("kimberly mendoza", "mno", "Calidad")
create_user("gabriela gaona", "pqr", "Calidad")
create_user("liu", "stu", "Terminado")
create_user("cesar vidal", "vwx", "Terminado")
create_user("ramon valvidia", "yz1", "Mantenimiento")
create_user("vigilancia", "234", "Administracion")
create_user("kaokin", "567", "Estampado")
create_user("rosy rivera", "890", "Enfermeria")
create_user("karla alfaro", "abc", "RH")
create_user("elizabet", "def", "RH-Nominas")
create_user("francisco garcia", "ghi", "Administracion")
create_user("yocelin ramirez", "jkl", "Administracion")
create_user("sandra luz", "mno", "RH")
create_user("jose rivera", "pqr", "Contabilidad")
create_user("pati gonzales", "pqr", "Contabilidad")
create_user("mari gonzales", "pqr", "Contabilidad")
