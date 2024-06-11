import os
import sys
import sqlite3

# Obtener el camino al directorio del ejecutable
if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS  # Si se ejecuta desde el ejecutable generado por PyInstaller
else:
    base_path = os.path.abspath(".")  # Si se ejecuta directamente el script de Python

# Construir el camino completo a la base de datos
db_path = os.path.join(base_path, 'tickets.db')

# Conectar a la base de datos
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Ahora puedes usar 'conn' y 'cursor' para interactuar con tu base de datos


import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
import sqlite3
from werkzeug.security import check_password_hash, generate_password_hash
from ttkthemes import ThemedTk  # Importa ThemedTk desde ttkthemes


class Database:
    @staticmethod
    def query(query, params=()):
        try:
            conn = sqlite3.connect('tickets.db')
            cursor = conn.cursor()
            cursor.execute(query, params)
            result = cursor.fetchall()
            conn.commit()
            return result
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Database error: {e}")
        finally:
            if 'conn' in locals():
                conn.close()

class LoginWindow:
    def __init__(self, master):
        self.master = master
        self.master.title('CTS - LOGIN')

        frame = ttk.Frame(master, padding="20")
        frame.pack(expand=True, fill='both')  

        # Campo de entrada de usuario y label
        ttk.Label(frame, text="Usuario:").grid(row=0, column=0, sticky=tk.E, padx=5, pady=5)
        self.username = ttk.Entry(frame)
        self.username.grid(row=0, column=1, padx=5, pady=5)

        # Campo de entrada de contraseña y label
        ttk.Label(frame, text="Contraseña:").grid(row=1, column=0, sticky=tk.E, padx=5, pady=5)
        self.password = ttk.Entry(frame, show='*')
        self.password.grid(row=1, column=1, padx=5, pady=5)

        # Botones "Show/Hide Password" y "Login"
        ttk.Button(frame, text='Show/Hide Password', command=self.toggle_password_visibility).grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(frame, text='Login', command=self.login).grid(row=3, column=0, columnspan=2, pady=10)


    def toggle_password_visibility(self):
        if self.password['show'] == '*':
            self.password['show'] = ''
        else:
            self.password['show'] = '*'

    def login(self):
        username = self.username.get().strip()
        password = self.password.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return

        role = self.check_credentials(username, password)

        if role:
            self.master.destroy()
            if role == 'admin':
                AdminWindow(ThemedTk(theme='clearlooks'))  # Cambia Tk a ThemedTk
            else:
                TerminalWindow(ThemedTk(theme='clearlooks'), username)  # Cambia Tk a ThemedTk
        else:
            messagebox.showerror("Error", "Invalid credentials")

    def check_credentials(self, username, password):
        result = Database.query("SELECT password, role FROM users WHERE username=?", (username,))
        if result and check_password_hash(result[0][0], password):
            return result[0][1]
        return None



class TerminalWindow:
    def __init__(self, master, username):
        self.master = master
        self.username = username
        self.master.title('CTS - Nuevo Ticket de Soporte')

        frame = ttk.Frame(master, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(frame, text="Title:").grid(row=0, column=0, sticky=tk.W)
        self.title = ttk.Entry(frame)
        self.title.grid(row=0, column=1, sticky=(tk.W, tk.E))

        ttk.Label(frame, text="Description:").grid(row=1, column=0, sticky=tk.W)
        self.description = tk.Text(frame, height=10, width=50)
        self.description.grid(row=1, column=1, sticky=(tk.W, tk.E))

        ttk.Button(frame, text='Submit', command=self.create_ticket).grid(row=2, column=1, sticky=tk.E, pady=10)
        ttk.Button(frame, text='Check Tickets', command=self.check_tickets).grid(row=3, column=1, sticky=tk.E, pady=10)

        self.master.update_idletasks()
        width = frame.winfo_reqwidth() + 40
        height = frame.winfo_reqheight() + 20
        self.master.geometry(f'{width}x{height}')

    def create_ticket(self):
        title = self.title.get().strip()
        description = self.description.get("1.0", "end").strip()

        if not title or not description:
            messagebox.showerror("Error", "Please enter both title and description")
            return

        user_id = self.get_user_id(self.username)

        try:
            Database.query("INSERT INTO tickets (user_id, title, description) VALUES (?, ?, ?)", (user_id, title, description))
            messagebox.showinfo("Success", "Ticket created successfully")
            self.title.delete(0, 'end') 
            self.description.delete('1.0', 'end')

        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Failed to create ticket: {e}")

    def get_user_id(self, username):
        result = Database.query("SELECT id FROM users WHERE username=?", (username,))
        return result[0][0] if result else None

    def check_tickets(self):
        tickets_info = Database.query("SELECT id, title, description, status, created_at FROM tickets WHERE user_id = ?", (self.get_user_id(self.username),))
        tickets_window = tk.Toplevel(self.master)
        UserTicketsWindow(tickets_window, tickets_info)

class UserTicketsWindow:
    def __init__(self, master, tickets_info):
        self.master = master
        self.master.title('CTS - Tickets de Usuarios')

        frame = ttk.Frame(master, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.tree = ttk.Treeview(frame, columns=('ID', 'Title', 'Description', 'Status', 'Created At'), show='headings')
        self.tree.grid(row=0, column=0, rowspan=4, sticky=(tk.W, tk.E, tk.N, tk.S))

        column_widths = [10, 100, 100, 100, 150]

        for i, col in enumerate(self.tree['columns']):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=column_widths[i], stretch=tk.NO)  # Evita que las columnas se ajusten automáticamente

        for ticket in tickets_info:
            truncated_description = self.truncate_description(ticket[2])  # Truncar la descripción si es demasiado larga
            self.tree.insert('', 'end', values=(ticket[0], ticket[1], truncated_description, ticket[3], ticket[4]))

        self.tree.bind("<Double-1>", self.show_ticket_details)  # Asociar evento de doble clic a la función show_ticket_details

    def truncate_description(self, description, max_length_percentage=0.10):
        max_length = int(len(description) * max_length_percentage)
        return description[:max_length] + "..."

    def show_ticket_details(self, event):
        selected_item = self.tree.selection()
        if not selected_item:
            return

        ticket_id = self.tree.item(selected_item)['values'][0]
        ticket_details = Database.query("SELECT title, description, status, created_at FROM tickets WHERE id=?", (ticket_id,))

        if ticket_details:
            details_window = tk.Toplevel(self.master)
            details_window.title("CTS - Detalles del ticket")

            frame = ttk.Frame(details_window, padding="10")
            frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

            ttk.Label(frame, text="Title:").grid(row=0, column=0, sticky=tk.W)
            ttk.Label(frame, text=ticket_details[0][0]).grid(row=0, column=1, sticky=tk.W)

            description_text = tk.Text(frame, height=5, width=50, wrap='word')
            description_text.insert(tk.END, ticket_details[0][1])
            description_text.grid(row=1, column=1, sticky=tk.W)
            description_text.config(state='disabled')

            ttk.Separator(frame, orient=tk.HORIZONTAL).grid(row=3, column=0, columnspan=2, sticky="ew", pady=10)

            ttk.Label(frame, text="Status:").grid(row=4, column=0, sticky=tk.W)
            ttk.Label(frame, text=ticket_details[0][2]).grid(row=4, column=1, sticky=tk.W)

            ttk.Label(frame, text="Created At:").grid(row=5, column=0, sticky=tk.W)
            ttk.Label(frame, text=ticket_details[0][3]).grid(row=5, column=1, sticky=tk.W)

        for child in frame.winfo_children():  # Configurar todos los labels para que sean de solo lectura
            description_text.config(state='disabled')

class AdminWindow:
    def __init__(self, master):
        self.master = master
        self.master.title('CTS - Manejador de tickets')

        frame = ttk.Frame(master, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.tree = ttk.Treeview(frame, columns=('ID', 'User', 'Title', 'Description', 'Status', 'Created At'), show='headings')
        self.tree.grid(row=0, column=0, rowspan=4, sticky=(tk.W, tk.E, tk.N, tk.S))

        column_widths = [7, 80, 200, 50, 60, 150]

        for i, col in enumerate(self.tree['columns']):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=column_widths[i])
            self.tree.bind("<Double-1>", self.show_ticket_details)
        
        ttk.Button(frame, text='Refresh', command=self.refresh).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Button(frame, text='Delete Selected', command=self.delete_selected).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Button(frame, text='Manage Users', command=self.open_manage_users_window).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Button(frame, text='Update Status', command=self.update_status).grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        
        self.refresh()

    def refresh(self):
        try:
            for row in self.tree.get_children():
                self.tree.delete(row)
            
            results = Database.query("SELECT tickets.id, users.username, tickets.title, tickets.description, tickets.status, tickets.created_at FROM tickets JOIN users ON tickets.user_id = users.id")
            for row in results:
                self.tree.insert('', 'end', values=row)
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Failed to refresh: {e}")


    def open_manage_users_window(self):
        manage_users_window = tk.Toplevel(self.master)
        manage_users_window.title('Manage Users')
        
        users_data = self.get_users_data()
        column_widths = [50, 100, 100]

        self.users_table = ttk.Treeview(manage_users_window, columns=('ID', 'Username', 'Role'), show='headings')
        self.users_table.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        for i, col in enumerate(self.users_table['columns']):
            self.users_table.heading(col, text=col)
            self.users_table.column(col, width=column_widths[i])

        for user in users_data:
            self.users_table.insert('', 'end', values=user)
        
        button_frame = ttk.Frame(manage_users_window)
        button_frame.grid(row=0, column=1, sticky=tk.N)

        ttk.Button(button_frame, text='Add User', command=self.add_user).pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(button_frame, text='Edit Password', command=self.edit_password).pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(button_frame, text='Delete User', command=self.delete_user).pack(fill=tk.X, padx=5, pady=5)

    def add_user(self):
        add_user_window = tk.Toplevel(self.master)
        add_user_window.title("Add User")
        
        frame = ttk.Frame(add_user_window, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        ttk.Label(frame, text="Username:").grid(row=0, column=0, sticky=tk.W)
        username_entry = ttk.Entry(frame)
        username_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(frame, text="Password:").grid(row=1, column=0, sticky=tk.W)
        password_entry = ttk.Entry(frame, show='*')
        password_entry.grid(row=1, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(frame, text="Role:").grid(row=2, column=0, sticky=tk.W)
        role_entry = ttk.Entry(frame)
        role_entry.grid(row=2, column=1, sticky=(tk.W, tk.E))
        
        ttk.Button(frame, text='Save', command=lambda: self.save_user(username_entry, password_entry, role_entry, add_user_window)).grid(row=3, column=1, sticky=tk.E, pady=10)

    def save_user(self, username_entry, password_entry, role_entry, window):
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        role = role_entry.get().strip()

        if not username or not password or not role:
            messagebox.showerror("Error", "Please fill out all fields")
            return

        hashed_password = generate_password_hash(password)
        try:
            Database.query("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
            messagebox.showinfo("Success", "User added successfully")
            window.destroy()
            self.refresh()
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Failed to add user: {e}")

    def edit_password(self):
        selected_item = self.users_table.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select a user to edit password")
            return
        
        user_id = self.users_table.item(selected_item)['values'][0]
        
        new_password = simpledialog.askstring("Edit Password", "Enter the new password:")
        if new_password is not None:
            hashed_password = generate_password_hash(new_password)
            try:
                Database.query("UPDATE users SET password=? WHERE id=?", (hashed_password, user_id))
                messagebox.showinfo("Success", "Password updated successfully")
            except sqlite3.Error as e:
                messagebox.showerror("Error", f"Failed to update password: {e}")

    def delete_user(self):
        selected_item = self.users_table.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select a user to delete")
            return
        
        user_id = self.users_table.item(selected_item)['values'][0]
        
        confirmation = messagebox.askyesno("Confirmation", f"Are you sure you want to delete user with ID {user_id}?")
        if confirmation:
            try:
                Database.query("DELETE FROM users WHERE id=?", (user_id,))
                messagebox.showinfo("Success", "User deleted successfully")
                self.refresh()
            except sqlite3.Error as e:
                messagebox.showerror("Error", f"Failed to delete user: {e}")

    def get_users_data(self):
        return Database.query("SELECT id, username, role FROM users")

    def update_status(self):
        selected_item = self.tree.selection()
        if not selected_item:
            return
        
        item = self.tree.item(selected_item)
        ticket_id = item['values'][0]

        def update_ticket_status(new_status):
            if new_status:
                Database.query("UPDATE tickets SET status=? WHERE id=?", (new_status, ticket_id))
                self.refresh()
                status_window.destroy()

        status_window = tk.Toplevel(self.master)
        status_window.title("Update Status")

        ttk.Button(status_window, text="New", command=lambda: update_ticket_status("New")).grid(row=0, column=0, padx=5, pady=5)
        ttk.Button(status_window, text="Open", command=lambda: update_ticket_status("Open")).grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(status_window, text="In Progress", command=lambda: update_ticket_status("In Progress")).grid(row=2, column=0, padx=5, pady=5)
        ttk.Button(status_window, text="Closed", command=lambda: update_ticket_status("Closed")).grid(row=3, column=0, padx=5, pady=5)

    def delete_selected(self):
        selected_items = self.tree.selection()
        if not selected_items:
            return
        
        confirmation = messagebox.askyesno("Confirmation", "Are you sure you want to delete the selected tickets?")
        if confirmation:
            for item in selected_items:
                ticket_id = self.tree.item(item)['values'][0]
                Database.query("DELETE FROM tickets WHERE id=?", (ticket_id,))
            self.refresh()

    def show_ticket_details(self, event):
        selected_item = self.tree.selection()
        if not selected_item:
            return
        
        item = self.tree.item(selected_item)
        ticket_id = item['values'][0]

        ticket_details = Database.query("SELECT * FROM tickets WHERE id=?", (ticket_id,))
        if ticket_details:
            details_window = tk.Toplevel(self.master)
            TicketDetailsWindow(details_window, ticket_details[0])

class TicketDetailsWindow:
    def __init__(self, master, ticket_details):
        self.master = master
        self.master.title('CTS - ADM Detalles del Ticket')
        
        frame = ttk.Frame(master, padding="20")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Título del Ticket
        ttk.Label(frame, text="Title:", font=("Arial", 12, "bold")).grid(row=0, column=0, sticky=tk.W)
        ttk.Label(frame, text=ticket_details[2], wraplength=600).grid(row=0, column=1, sticky=tk.W)

        # Descripción del Ticket
        ttk.Label(frame, text="Description:", font=("Arial", 12, "bold")).grid(row=1, column=0, sticky=tk.W, pady=(10, 5))
        description_frame = tk.Frame(frame, highlightbackground="gray", highlightthickness=1)
        description_frame.grid(row=1, column=1, sticky=tk.W)
        description_text = tk.Text(description_frame, wrap="word", height=5, width=60)
        description_text.grid(row=0, column=0, sticky=tk.W)
        description_text.insert(tk.END, ticket_details[3])
        description_text.config(state="disabled")

        # Estado del Ticket
        ttk.Label(frame, text="Status:", font=("Arial", 12, "bold")).grid(row=2, column=0, sticky=tk.W, pady=(10, 5))
        status_text = ticket_details[4]
        status_label = ttk.Label(frame, text=status_text)
        status_label.grid(row=2, column=1, sticky=tk.W)
        if status_text.lower() == "open":
            status_label.config(font="bold", foreground="green")
        elif status_text.lower() == "closed":
            status_label.config(font="bold", foreground="red")

        # Fecha de creación del Ticket
        ttk.Label(frame, text="Created At:", font=("Arial", 12, "bold")).grid(row=3, column=0, sticky=tk.W, pady=(10, 0))
        ttk.Label(frame, text=ticket_details[5]).grid(row=3, column=1, sticky=tk.W)



if __name__ == '__main__':
    root = ThemedTk(theme='clearlooks')  # Cambia Tk a ThemedTk
    LoginWindow(root)
    style = ttk.Style()
    style.configure('.', font=('Open Sans', 11))
    root.mainloop()
