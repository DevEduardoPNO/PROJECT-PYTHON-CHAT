import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime
import tkinter as tk
from tkinter import scrolledtext

# ---------------------------
# Inicializa Firebase
# ---------------------------
cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

# ---------------------------
# Funções de usuários
# ---------------------------
def cadastrar_usuario(nome, email, senha):
    doc_ref = db.collection("Usuarios").document(email)
    doc_ref.set({
        "nome": nome,
        "senha": senha
    })

def login_usuario(email, senha):
    doc_ref = db.collection("Usuarios").document(email)
    doc = doc_ref.get()
    if doc.exists and doc.to_dict()["senha"] == senha:
        return True
    return False

# ---------------------------
# Funções de chat
# ---------------------------
def enviar_mensagem(remetente, destinatario, mensagem):
    db.collection("Chats").document().set({
        "remetente": remetente,
        "destinatario": destinatario,
        "mensagem": mensagem,
        "timestamp": datetime.now()
    })

def ler_mensagens(usuario1, usuario2):
    chats_ref = db.collection("Chats").order_by("timestamp")
    mensagens = []
    for doc in chats_ref.stream():
        data = doc.to_dict()
        if (data["remetente"] == usuario1 and data["destinatario"] == usuario2) or \
        (data["remetente"] == usuario2 and data["destinatario"] == usuario1):
            mensagens.append(f'{data["remetente"]}: {data["mensagem"]}')
    return mensagens

# ---------------------------
# Cria usuários de teste (só para teste inicial)
# ---------------------------
cadastrar_usuario("Eduardo", "eduardo@email.com", "123")
cadastrar_usuario("Joao", "joao@email.com", "123")

# ---------------------------
# Interface Tkinter
# ---------------------------
usuario_logado = None
destinatario_logado = None

def entrar_chat():
    global usuario_logado, destinatario_logado
    usuario = entrada_usuario.get()
    senha = entrada_senha.get()
    destinatario = entrada_destino.get()
    if login_usuario(usuario, senha):
        usuario_logado = usuario
        destinatario_logado = destinatario
        atualizar_chat()
        login_frame.pack_forget()
        chat_frame.pack()
    else:
        lbl_status.config(text="❌ Login inválido!")

def enviar():
    msg = entrada_msg.get()
    if msg:
        enviar_mensagem(usuario_logado, destinatario_logado, msg)
        entrada_msg.delete(0, tk.END)
        atualizar_chat()

def atualizar_chat():
    if usuario_logado and destinatario_logado:
        chat_box.config(state="normal")
        chat_box.delete(1.0, tk.END)
        mensagens = ler_mensagens(usuario_logado, destinatario_logado)
        for m in mensagens:
            chat_box.insert(tk.END, m + "\n")
        chat_box.config(state="disabled")
        root.after(2000, atualizar_chat)  # Atualiza a cada 2s

# ---------------------------
# Interface gráfica
# ---------------------------
root = tk.Tk()
root.title("Chat Funcional Firebase")

# Frames
login_frame = tk.Frame(root)
chat_frame = tk.Frame(root)

# Frame de login
tk.Label(login_frame, text="Usuário (email):").pack()
entrada_usuario = tk.Entry(login_frame)
entrada_usuario.pack()
tk.Label(login_frame, text="Senha:").pack()
entrada_senha = tk.Entry(login_frame, show="*")
entrada_senha.pack()
tk.Label(login_frame, text="Destinatário (email):").pack()
entrada_destino = tk.Entry(login_frame)
entrada_destino.pack()
btn_entrar = tk.Button(login_frame, text="Entrar", command=entrar_chat)
btn_entrar.pack()
lbl_status = tk.Label(login_frame, text="")
lbl_status.pack()
login_frame.pack()

# Frame de chat
chat_box = scrolledtext.ScrolledText(chat_frame, state="disabled", width=50, height=20)
chat_box.pack()
entrada_msg = tk.Entry(chat_frame, width=40)
entrada_msg.pack(side=tk.LEFT)
btn_enviar = tk.Button(chat_frame, text="Enviar", command=enviar)
btn_enviar.pack(side=tk.LEFT)

# ---------------------------
# Inicia a interface
# ---------------------------
root.mainloop()
