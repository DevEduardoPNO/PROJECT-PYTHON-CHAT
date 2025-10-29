import os
import base64
import hashlib
import hmac
import json
from datetime import datetime
import secrets
import threading

import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText

# Firebase
import firebase_admin
from firebase_admin import credentials, firestore

# Tenta importar cryptography para Fernet (criptografia forte)
try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

# ---------------------------
# Configurações de segurança
# ---------------------------
SERVER_SIDE_KEY = b"change_this_to_a_random_secret_of_at_least_32_bytes"
PBKDF2_ITERS = 200_000

# ---------------------------
# Inicializa Firebase com tratamento robusto
# ---------------------------
if not os.path.exists('serviceAccountKey.json'):
    messagebox.showerror('Erro', 'Arquivo serviceAccountKey.json não encontrado na pasta do script.')
    raise SystemExit(1)

try:
    cred = credentials.Certificate('serviceAccountKey.json')
    firebase_admin.initialize_app(cred)
    db = firestore.client()
except Exception as e:
    messagebox.showerror('Erro Firebase', f'Não foi possível inicializar o Firebase:\n{e}')
    raise SystemExit(1)

# ---------------------------
# Utils: senha e criptografia
# ---------------------------

def generate_password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERS, dklen=32)
    return base64.b64encode(salt + dk).decode('utf-8')


def verify_password_hash(password: str, stored: str) -> bool:
    try:
        data = base64.b64decode(stored.encode('utf-8'))
        salt, dk = data[:16], data[16:]
        newdk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERS, dklen=32)
        return hmac.compare_digest(dk, newdk)
    except Exception:
        return False


def derive_key_from_passphrase(passphrase: str) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', passphrase.encode('utf-8'), SERVER_SIDE_KEY[:16], 100_000, dklen=32)


def encrypt_message(plaintext: str, passphrase: str = None) -> dict:
    if not plaintext:
        return {'cipher': '', 'enc': False}
    if passphrase and HAS_CRYPTO:
        key = base64.urlsafe_b64encode(derive_key_from_passphrase(passphrase))
        f = Fernet(key)
        token = f.encrypt(plaintext.encode('utf-8'))
        return {'cipher': base64.b64encode(token).decode('utf-8'), 'method': 'fernet', 'enc': True}
    elif passphrase and not HAS_CRYPTO:
        key = derive_key_from_passphrase(passphrase)
        pt = plaintext.encode('utf-8')
        stream = bytes(pt[i] ^ key[i % len(key)] for i in range(len(pt)))
        mac = hmac.new(SERVER_SIDE_KEY, stream, hashlib.sha256).hexdigest()
        return {'cipher': base64.b64encode(stream).decode('utf-8'), 'method': 'xor_hmac', 'enc': True, 'mac': mac}
    else:
        data = plaintext.encode('utf-8')
        mac = hmac.new(SERVER_SIDE_KEY, data, hashlib.sha256).hexdigest()
        return {'cipher': base64.b64encode(data).decode('utf-8'), 'method': 'plain_mac', 'enc': False, 'mac': mac}


def decrypt_message(obj: dict, passphrase: str = None) -> str:
    try:
        if not obj or 'cipher' not in obj:
            return ''
        method = obj.get('method')
        b = base64.b64decode(obj['cipher'].encode('utf-8'))
        if obj.get('enc') and passphrase and method == 'fernet' and HAS_CRYPTO:
            key = base64.urlsafe_b64encode(derive_key_from_passphrase(passphrase))
            f = Fernet(key)
            return f.decrypt(b).decode('utf-8')
        elif obj.get('enc') and passphrase and method == 'xor_hmac' and not HAS_CRYPTO:
            mac = obj.get('mac')
            calc = hmac.new(SERVER_SIDE_KEY, b, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac or '', calc):
                return '[Mensagem corrompida: MAC inválido]'
            key = derive_key_from_passphrase(passphrase)
            pt = bytes(b[i] ^ key[i % len(key)] for i in range(len(b)))
            return pt.decode('utf-8', errors='replace')
        else:
            mac = obj.get('mac')
            calc = hmac.new(SERVER_SIDE_KEY, b, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(mac or '', calc):
                return '[Mensagem corrompida: MAC inválido]'
            return b.decode('utf-8', errors='replace')
    except Exception as e:
        return f'[Erro ao decifrar: {e}]'

# ---------------------------
# Firestore helpers (corrigidos para conversas bidirecionais)
# ---------------------------

def create_user(nome: str, email: str, senha: str) -> (bool, str):
    try:
        ref = db.collection('Usuarios').document(email)
        if ref.get().exists:
            return False, 'E-mail já cadastrado.'
        senha_hash = generate_password_hash(senha)
        now = datetime.utcnow()
        ref.set({
            'nome': nome,
            'email': email,
            'senha_hash': senha_hash,
            'status': 'offline',
            'ultima_vez': now,
            'contacts': [],
            'blocked': []
        })
        return True, 'Cadastro realizado com sucesso.'
    except Exception as e:
        return False, f'Erro ao cadastrar: {e}'


def authenticate_user(email: str, senha: str) -> (bool, str):
    try:
        ref = db.collection('Usuarios').document(email)
        doc = ref.get()
        if not doc.exists:
            return False, 'Usuário não encontrado.'
        data = doc.to_dict()
        if verify_password_hash(senha, data.get('senha_hash', '')):
            ref.update({'status': 'online', 'ultima_vez': datetime.utcnow()})
            return True, data.get('nome', email)
        return False, 'Senha incorreta.'
    except Exception as e:
        return False, f'Erro ao autenticar: {e}'


def update_user_status(email: str, status: str):
    try:
        db.collection('Usuarios').document(email).update({'status': status, 'ultima_vez': datetime.utcnow()})
    except Exception:
        pass

# Ao enviar mensagem, garantimos que destinatário esteja correto e usamos uma única função

def send_message(remetente: str, destinatario: str, texto_obj: dict) -> bool:
    try:
        if not destinatario:
            print('send_message: destinatario inválido')
            return False
        doc = {
            'remetente': remetente,
            'destinatario': destinatario,
            'mensagem': texto_obj,
            'timestamp': datetime.utcnow(),
            'lido_por': []
        }
        db.collection('Chats').document().set(doc)
        return True
    except Exception as e:
        print('Erro send_message:', e)
        return False


def fetch_messages(user1: str, user2: str):
    try:
        msgs = []
        # Consulta 1: user1 -> user2
        q1 = db.collection('Chats').where('remetente', '==', user1).where('destinatario', '==', user2).stream()
        # Consulta 2: user2 -> user1
        q2 = db.collection('Chats').where('remetente', '==', user2).where('destinatario', '==', user1).stream()
        for d in q1:
            data = d.to_dict()
            data['_id'] = d.id
            msgs.append(data)
        for d in q2:
            data = d.to_dict()
            data['_id'] = d.id
            msgs.append(data)
        # ordenar por timestamp localmente
        msgs.sort(key=lambda x: x.get('timestamp') or datetime.utcnow())
        return msgs
    except Exception as e:
        print('Erro fetch_messages:', e)
        return []

# Mark read (usa _id quando disponível)

def mark_message_read(msg_doc_id: str, email: str):
    try:
        ref = db.collection('Chats').document(msg_doc_id)
        doc = ref.get()
        if not doc.exists:
            return
        data = doc.to_dict()
        lido = set(data.get('lido_por', []))
        lido.add(email)
        ref.update({'lido_por': list(lido)})
    except Exception:
        pass

# Contacts

def add_contact(user_email: str, contact_email: str) -> (bool, str):
    try:
        user_ref = db.collection('Usuarios').document(user_email)
        if not user_ref.get().exists:
            return False, 'Usuário não existe.'
        contact_ref = db.collection('Usuarios').document(contact_email)
        if not contact_ref.get().exists:
            return False, 'Contato não encontrado.'
        data = user_ref.get().to_dict()
        contacts = data.get('contacts', [])
        blocked = data.get('blocked', [])
        if contact_email in contacts:
            return False, 'Contato já adicionado.'
        if contact_email in blocked:
            return False, 'Contato está bloqueado.'
        contacts.append(contact_email)
        user_ref.update({'contacts': contacts})
        return True, 'Contato adicionado.'
    except Exception as e:
        return False, f'Erro: {e}'


def remove_contact(user_email: str, contact_email: str) -> (bool, str):
    try:
        user_ref = db.collection('Usuarios').document(user_email)
        data = user_ref.get().to_dict()
        contacts = data.get('contacts', [])
        if contact_email in contacts:
            contacts.remove(contact_email)
            user_ref.update({'contacts': contacts})
            return True, 'Contato removido.'
        return False, 'Contato não encontrado na sua lista.'
    except Exception as e:
        return False, f'Erro: {e}'


def block_contact(user_email: str, contact_email: str) -> (bool, str):
    try:
        user_ref = db.collection('Usuarios').document(user_email)
        data = user_ref.get().to_dict()
        blocked = set(data.get('blocked', []))
        blocked.add(contact_email)
        contacts = set(data.get('contacts', []))
        contacts.discard(contact_email)
        user_ref.update({'blocked': list(blocked), 'contacts': list(contacts)})
        return True, 'Contato bloqueado.'
    except Exception as e:
        return False, f'Erro: {e}'

# ---------------------------
# UI: ChatGUI (mantive recursos e corrigi envio/leitura de mensagens)
# ---------------------------

class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title('Messenger Pro')
        self.root.geometry('1000x700')
        self.theme = 'light'
        self.current_user = None
        self.current_partner = None
        self.conv_passphrase = None
        self.last_messages_hash = None
        self.notification_enabled = True

        self.build_ui()
        # start auto-refresh
        self.running = True
        self.thread = threading.Thread(target=self.auto_refresh_loop, daemon=True)
        self.thread.start()

    def build_ui(self):
        self.left_frame = tk.Frame(self.root, width=300)
        self.left_frame.pack(side='left', fill='y')
        self.right_frame = tk.Frame(self.root)
        self.right_frame.pack(side='right', fill='both', expand=True)

        prof = tk.Frame(self.left_frame, pady=10)
        prof.pack(fill='x')
        self.lbl_profile = tk.Label(prof, text='Não conectado', font=('Segoe UI', 12, 'bold'))
        self.lbl_profile.pack()

        search_frame = tk.Frame(self.left_frame)
        search_frame.pack(fill='x', padx=8, pady=6)
        tk.Label(search_frame, text='Buscar contatos').pack(anchor='w')
        self.search_var = tk.StringVar()
        self.entry_search = tk.Entry(search_frame, textvariable=self.search_var)
        self.entry_search.pack(fill='x')
        self.search_var.trace_add('write', lambda *a: self.refresh_contacts())

        self.contacts_box = tk.Listbox(self.left_frame, height=30)
        self.contacts_box.pack(fill='both', expand=True, padx=8, pady=6)
        self.contacts_box.bind('<Double-Button-1>', lambda e: self.open_conversation())

        btns = tk.Frame(self.left_frame)
        btns.pack(fill='x', padx=8, pady=6)
        ttk.Button(btns, text='Adicionar', command=self.add_contact_dialog).pack(side='left', padx=4)
        ttk.Button(btns, text='Apagar', command=self.delete_contact_ui).pack(side='left', padx=4)
        ttk.Button(btns, text='Bloquear', command=self.block_contact_ui).pack(side='left', padx=4)

        bottom = tk.Frame(self.left_frame)
        bottom.pack(fill='x', padx=8, pady=6)
        ttk.Button(bottom, text='Login', command=self.show_login).pack(side='left', padx=4)
        ttk.Button(bottom, text='Criar conta', command=self.show_register).pack(side='left', padx=4)
        ttk.Button(bottom, text='Tema', command=self.toggle_theme).pack(side='right', padx=4)

        topbar = tk.Frame(self.right_frame, height=60)
        topbar.pack(fill='x')
        self.lbl_conv = tk.Label(topbar, text='Nenhuma conversa aberta', font=('Segoe UI', 14, 'bold'))
        self.lbl_conv.pack(side='left', padx=10)
        self.lbl_status = tk.Label(topbar, text='Status: —')
        self.lbl_status.pack(side='right', padx=10)

        mid = tk.Frame(self.right_frame)
        mid.pack(fill='both', expand=True)
        self.txt_messages = ScrolledText(mid, state='disabled', wrap='word')
        self.txt_messages.pack(fill='both', expand=True, padx=10, pady=10)

        composer = tk.Frame(self.right_frame)
        composer.pack(fill='x', padx=10, pady=10)
        self.entry_msg = tk.Entry(composer)
        self.entry_msg.pack(side='left', fill='x', expand=True, padx=(0,8))
        ttk.Button(composer, text='Enviar', command=self.send_message_ui).pack(side='left', padx=6)
        ttk.Button(composer, text='Senha conv.', command=self.set_conversation_pass).pack(side='left', padx=6)

        self.apply_theme()

    # Theme
    def toggle_theme(self):
        self.theme = 'dark' if self.theme == 'light' else 'light'
        self.apply_theme()

    def apply_theme(self):
        if self.theme == 'light':
            bg = '#f8f9fb'; fg = '#111827'; widget_bg = '#ffffff'
        else:
            bg = '#1f2937'; fg = '#e5e7eb'; widget_bg = '#374151'
        self.root.configure(bg=bg)
        for w in [self.left_frame, self.right_frame]:
            try:
                w.configure(bg=bg)
            except Exception:
                pass
        for label in [self.lbl_profile, self.lbl_conv, self.lbl_status]:
            try:
                label.configure(bg=bg, fg=fg)
            except Exception:
                pass
        try:
            self.txt_messages.configure(bg=widget_bg, fg=fg, insertbackground=fg)
            self.contacts_box.configure(bg=widget_bg, fg=fg)
            self.entry_msg.configure(bg=widget_bg, fg=fg, insertbackground=fg)
            self.entry_search.configure(bg=widget_bg, fg=fg)
        except Exception:
            pass

    # Register / Login
    def show_register(self):
        win = tk.Toplevel(self.root)
        win.title('Criar conta')
        ttk.Label(win, text='Nome').pack(padx=8, pady=4)
        name_e = ttk.Entry(win)
        name_e.pack(padx=8, pady=4)
        ttk.Label(win, text='E-mail (ID)').pack(padx=8, pady=4)
        email_e = ttk.Entry(win)
        email_e.pack(padx=8, pady=4)
        ttk.Label(win, text='Senha').pack(padx=8, pady=4)
        pass_e = ttk.Entry(win, show='*')
        pass_e.pack(padx=8, pady=4)

        def do_register():
            nome = name_e.get().strip(); email = email_e.get().strip(); senha = pass_e.get().strip()
            if not nome or not email or not senha:
                messagebox.showwarning('Atenção', 'Preencha todos os campos')
                return
            ok, msg = create_user(nome, email, senha)
            if ok:
                messagebox.showinfo('Sucesso', msg)
                win.destroy()
            else:
                messagebox.showerror('Erro', msg)

        ttk.Button(win, text='Criar', command=do_register).pack(pady=8)

    def show_login(self):
        win = tk.Toplevel(self.root)
        win.title('Login')
        ttk.Label(win, text='E-mail').pack(padx=8, pady=4)
        email_e = ttk.Entry(win)
        email_e.pack(padx=8, pady=4)
        ttk.Label(win, text='Senha').pack(padx=8, pady=4)
        pass_e = ttk.Entry(win, show='*')
        pass_e.pack(padx=8, pady=4)

        def do_login():
            email = email_e.get().strip(); senha = pass_e.get().strip()
            ok, resp = authenticate_user(email, senha)
            if ok:
                self.current_user = {'email': email, 'nome': resp}
                self.lbl_profile.configure(text=f"{resp} <{email}> • online")
                win.destroy()
                self.refresh_contacts()
            else:
                messagebox.showerror('Erro', resp)

        ttk.Button(win, text='Entrar', command=do_login).pack(pady=8)

    # Contacts
    def refresh_contacts(self):
        self.contacts_box.delete(0, tk.END)
        if not self.current_user:
            return
        try:
            doc = db.collection('Usuarios').document(self.current_user['email']).get()
            data = doc.to_dict()
            contacts = data.get('contacts', [])
            query = self.search_var.get().strip().lower()
            for c in contacts:
                c_doc = db.collection('Usuarios').document(c).get()
                if not c_doc.exists:
                    continue
                c_data = c_doc.to_dict()
                display = f"{c_data.get('nome', c)} <{c}>"
                if query and query not in display.lower():
                    continue
                self.contacts_box.insert(tk.END, display)
        except Exception as e:
            print('refresh_contacts error', e)

    def add_contact_dialog(self):
        if not self.current_user:
            messagebox.showinfo('Info', 'Faça login primeiro')
            return
        email = simple_input(self.root, 'Digite o e-mail do contato:')
        if not email:
            return
        ok, msg = add_contact(self.current_user['email'], email)
        if ok:
            messagebox.showinfo('Sucesso', msg)
            self.refresh_contacts()
        else:
            messagebox.showerror('Erro', msg)

    def delete_contact_ui(self):
        if not self.current_user:
            messagebox.showinfo('Info', 'Faça login primeiro')
            return
        sel = self.contacts_box.curselection()
        if not sel:
            messagebox.showwarning('Atenção', 'Selecione um contato')
            return
        display = self.contacts_box.get(sel[0])
        email = extract_email(display)
        confirm = messagebox.askyesno('Confirmar', f'Deseja apagar o contato {display}?')
        if not confirm:
            return
        ok, msg = remove_contact(self.current_user['email'], email)
        if ok:
            messagebox.showinfo('Sucesso', msg)
            self.refresh_contacts()
        else:
            messagebox.showerror('Erro', msg)

    def block_contact_ui(self):
        if not self.current_user:
            messagebox.showinfo('Info', 'Faça login primeiro')
            return
        sel = self.contacts_box.curselection()
        if not sel:
            messagebox.showwarning('Atenção', 'Selecione um contato')
            return
        display = self.contacts_box.get(sel[0])
        email = extract_email(display)
        confirm = messagebox.askyesno('Confirmar', f'Deseja BLOQUEAR o contato {display}?')
        if not confirm:
            return
        ok, msg = block_contact(self.current_user['email'], email)
        if ok:
            messagebox.showinfo('Sucesso', msg)
            self.refresh_contacts()
        else:
            messagebox.showerror('Erro', msg)

    # Conversation actions
    def open_conversation(self):
        sel = self.contacts_box.curselection()
        if not sel:
            return
        display = self.contacts_box.get(sel[0])
        email = extract_email(display)
        self.current_partner = {'email': email}
        try:
            pd = db.collection('Usuarios').document(email).get().to_dict()
            self.current_partner['nome'] = pd.get('nome', email)
            status = pd.get('status', 'offline')
            last = pd.get('ultima_vez')
            last_str = format_datetime(last) if last else '—'
            self.lbl_status.configure(text=f"{status} • Última vez: {last_str}")
        except Exception:
            self.lbl_status.configure(text='Status: —')
        self.lbl_conv.configure(text=f"Conversando com {self.current_partner.get('nome')} <{email}>")
        self.txt_messages.configure(state='normal')
        self.txt_messages.delete('1.0', tk.END)
        self.txt_messages.configure(state='disabled')
        self.load_messages(force=True)

    def set_conversation_pass(self):
        if not self.current_partner:
            messagebox.showinfo('Info', 'Abra uma conversa primeiro')
            return
        pw = simple_input(self.root, 'Digite a senha da conversa (deixe em branco para desativar)')
        self.conv_passphrase = pw if pw else None
        if self.conv_passphrase and not HAS_CRYPTO:
            messagebox.showwarning('Aviso', 'cryptography não está instalada — usando fallback menos seguro')
        self.load_messages(force=True)

    def send_message_ui(self):
        if not self.current_user:
            messagebox.showinfo('Info', 'Faça login primeiro')
            return
        if not self.current_partner:
            messagebox.showinfo('Info', 'Abra uma conversa primeiro')
            return
        text = self.entry_msg.get().strip()
        if not text:
            return
        # Garantia: destinatário correto
        destinatario = self.current_partner.get('email')
        payload = json.dumps({'text': text})
        cipher_obj = encrypt_message(payload, self.conv_passphrase)
        ok = send_message(self.current_user['email'], destinatario, cipher_obj)
        if ok:
            self.entry_msg.delete(0, tk.END)
            self.notify_local('Mensagem enviada')
            self.load_messages(force=True)
        else:
            messagebox.showerror('Erro', 'Falha ao enviar mensagem')

    def load_messages(self, force=False):
        if not self.current_user or not self.current_partner:
            return
        msgs = fetch_messages(self.current_user['email'], self.current_partner['email'])
        h = hashlib.sha256(''.join(str(m.get('timestamp')) for m in msgs).encode('utf-8')).hexdigest()
        if not force and h == self.last_messages_hash:
            return
        self.last_messages_hash = h
        self.txt_messages.configure(state='normal')
        self.txt_messages.delete('1.0', tk.END)
        for m in msgs:
            remet = m.get('remetente')
            ts = m.get('timestamp')
            ts_str = format_datetime(ts)
            raw = m.get('mensagem')
            text = decrypt_message(raw, self.conv_passphrase)
            try:
                parsed = json.loads(text)
                text_display = parsed.get('text', '')
            except Exception:
                text_display = text
            prefix = 'Você' if remet == self.current_user['email'] else remet
            line = f"[{ts_str}] {prefix}: {text_display}\n"
            self.txt_messages.insert(tk.END, line)
            # marca como lido (se for de parceiro)
            try:
                if remet != self.current_user['email']:
                    mid = m.get('_id')
                    if mid:
                        mark_message_read(mid, self.current_user['email'])
            except Exception:
                pass
        self.txt_messages.configure(state='disabled')
        if msgs:
            last = msgs[-1]
            if last.get('remetente') != self.current_user['email']:
                self.notify_new_message(last)

    def notify_new_message(self, msg):
        if not self.notification_enabled:
            return
        try:
            remet = msg.get('remetente')
            text_obj = msg.get('mensagem')
            preview = decrypt_message(text_obj, self.conv_passphrase)
            try:
                preview_text = json.loads(preview).get('text', '')
            except Exception:
                preview_text = preview
            if self.current_partner and remet == self.current_partner.get('email'):
                self.lbl_status.configure(text='Nova mensagem!')
            else:
                messagebox.showinfo('Nova mensagem', f'Nova mensagem de {remet}:\n{preview_text[:120]}')
            self.root.bell()
        except Exception as e:
            print('notify error', e)

    def notify_local(self, text):
        if self.notification_enabled:
            self.root.bell()

    def auto_refresh_loop(self):
        while self.running:
            try:
                if self.current_user and self.current_partner:
                    self.load_messages()
                if self.current_user:
                    self.refresh_contacts()
                    try:
                        u = db.collection('Usuarios').document(self.current_user['email']).get().to_dict()
                        self.lbl_profile.configure(text=f"{u.get('nome')} <{u.get('email')}> • {u.get('status')}")
                    except Exception:
                        pass
                threading.Event().wait(3.5)
            except Exception as e:
                print('auto_refresh_loop error', e)
                threading.Event().wait(3.5)

    def stop(self):
        self.running = False

# ---------------------------
# Helpers UI & util
# ---------------------------

def simple_input(parent, prompt):
    win = tk.Toplevel(parent)
    win.grab_set()
    win.title('Entrada')
    tk.Label(win, text=prompt).pack(padx=10, pady=8)
    e = tk.Entry(win, width=40)
    e.pack(padx=10, pady=6)
    res = {'val': None}

    def ok():
        res['val'] = e.get()
        win.destroy()

    tk.Button(win, text='OK', command=ok).pack(pady=8)
    parent.wait_window(win)
    return res['val']


def extract_email(display: str) -> str:
    if '<' in display and '>' in display:
        return display.split('<')[1].split('>')[0]
    return display


def format_datetime(ts):
    if not ts:
        return '—'
    try:
        if isinstance(ts, datetime):
            return ts.strftime('%Y-%m-%d %H:%M:%S')
        try:
            return ts.ToDatetime().strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return str(ts)
    except Exception:
        return str(ts)

# ---------------------------
# Inicialização
# ---------------------------

def main():
    root = tk.Tk()
    app = ChatGUI(root)
    def on_close():
        if app.current_user:
            try:
                update_user_status(app.current_user['email'], 'offline')
            except Exception:
                pass
        app.stop()
        root.destroy()
    root.protocol('WM_DELETE_WINDOW', on_close)
    root.mainloop()

if __name__ == '__main__':
    main()
