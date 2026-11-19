#!/usr/bin/env python3
"""
Cliente de Acceso Remoto — se ejecuta en la PC desde la que se controla.

  * Muestra la pantalla remota ajustada a la ventana.
  * Envía mouse (mover, clics, arrastrar, rueda) y teclado.
  * Escribe en el remoto el texto del portapapeles local.
  * Envía archivos al remoto.
  * Verifica la huella del certificado del servidor (como SSH).

Uso:
    python cliente.py
"""
import asyncio
import io
import json
import os
import queue
import socket
import ssl
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageTk

import protocolo as P

ES_WINDOWS = sys.platform == "win32"
ES_MAC = sys.platform == "darwin"
DIR_DATOS = Path.home() / ".acceso_remoto"
ARCHIVO_HOSTS = DIR_DATOS / "hosts_conocidos.json"
ARCHIVO_AJUSTES = DIR_DATOS / "cliente.json"
BLOQUE_ARCHIVO = 256 * 1024


def leer_json(ruta, defecto):
    try:
        return json.loads(ruta.read_text("utf-8"))
    except (OSError, ValueError):
        return defecto


def escribir_json(ruta, datos):
    DIR_DATOS.mkdir(parents=True, exist_ok=True)
    ruta.write_text(json.dumps(datos, indent=2, ensure_ascii=False), "utf-8")


class ErrorAutenticacion(Exception):
    pass


# ------------------------------------------------------------------------ red
class Red:
    """Toda la comunicación corre en un hilo con su propio bucle asyncio."""

    def __init__(self, eventos: queue.Queue):
        self.eventos = eventos
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self.loop.run_forever, daemon=True, name="red").start()
        self.reader = None
        self.writer = None
        self._cuadro = None
        self._lock = threading.Lock()
        self._cerrando = True
        self._tarea = None

    def ejecutar(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    async def abrir(self, host, puerto):
        await self._cerrar()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # Certificado autofirmado: se valida por huella (ver App._verificar_huella)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(host, puerto, ssl=ctx), timeout=10)
        der = self.writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        return P.huella(der)

    async def autenticar(self, password):
        tipo, datos = await asyncio.wait_for(P.leer(self.reader), 15)
        hola = P.a_json(datos)
        if tipo == P.MSG_AUTH_FAIL:
            await self._cerrar()
            raise ErrorAutenticacion(hola.get("error", "Acceso denegado"))
        if tipo != P.MSG_HELLO:
            raise P.ErrorProtocolo("Respuesta inesperada del servidor")
        if hola.get("version") != P.VERSION:
            raise P.ErrorProtocolo(f"Versión incompatible (servidor v{hola.get('version')}, "
                                   f"cliente v{P.VERSION})")
        iteraciones = int(hola["iter"])
        if not 1_000 <= iteraciones <= 2_000_000:
            raise P.ErrorProtocolo("Parámetros de autenticación inválidos")
        clave = await asyncio.to_thread(P.derivar_clave, password, hola["salt"], iteraciones)
        self.writer.write(P.empaquetar(P.MSG_AUTH, {
            "resp": P.respuesta_desafio(clave, hola["nonce"]), "equipo": socket.gethostname()}))
        await self.writer.drain()

        tipo, datos = await asyncio.wait_for(P.leer(self.reader), 30)
        info = P.a_json(datos)
        if tipo == P.MSG_AUTH_FAIL:
            await self._cerrar()
            raise ErrorAutenticacion(info.get("error", "Acceso denegado"))
        if tipo != P.MSG_AUTH_OK:
            raise P.ErrorProtocolo("Respuesta inesperada del servidor")
        self._cerrando = False
        self._tarea = asyncio.create_task(self._recibir())
        return info

    async def _recibir(self):
        motivo = "El servidor cerró la conexión"
        try:
            while True:
                tipo, datos = await P.leer(self.reader)
                if tipo == P.MSG_FRAME:
                    with self._lock:
                        self._cuadro = datos  # solo interesa el último
                elif tipo == P.MSG_INFO:
                    self.eventos.put(("info", P.a_json(datos)))
        except asyncio.CancelledError:
            motivo = None
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError, OSError):
            pass
        except Exception as e:
            motivo = f"Error de comunicación: {e}"
        finally:
            if not self._cerrando and motivo:
                self.eventos.put(("cerrada", motivo))
            if self.writer:
                self.writer.close()

    def tomar_cuadro(self):
        with self._lock:
            c, self._cuadro = self._cuadro, None
        return c

    def enviar(self, tipo, payload=b""):
        datos = P.empaquetar(tipo, payload)
        self.loop.call_soon_threadsafe(self._escribir, datos)

    def _escribir(self, datos):
        if self.writer and not self.writer.is_closing():
            self.writer.write(datos)

    async def enviar_archivo(self, ruta):
        tam = os.path.getsize(ruta)
        self.writer.write(P.empaquetar(P.MSG_FILE_START, {"name": os.path.basename(ruta), "size": tam}))
        enviados, ultimo = 0, 0.0
        with open(ruta, "rb") as f:
            while bloque := f.read(BLOQUE_ARCHIVO):
                self.writer.write(P.empaquetar(P.MSG_FILE_CHUNK, bloque))
                await self.writer.drain()
                enviados += len(bloque)
                if time.monotonic() - ultimo > 0.25:
                    self.eventos.put(("progreso", enviados, tam))
                    ultimo = time.monotonic()
        self.writer.write(P.empaquetar(P.MSG_FILE_END))
        await self.writer.drain()
        self.eventos.put(("progreso", tam, tam))

    def cerrar(self):
        self._cerrando = True
        self.ejecutar(self._cerrar())

    async def _cerrar(self):
        self._cerrando = True
        if self._tarea:
            self._tarea.cancel()
            self._tarea = None
        if self.writer:
            self.writer.close()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), 2)
            except Exception:
                pass
        self.reader = self.writer = None
        with self._lock:
            self._cuadro = None


# ------------------------------------------------------------------------- UI
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Acceso Remoto — Cliente")
        self.geometry("1280x800")
        self.minsize(640, 420)
        self.eventos = queue.Queue()
        self.red = Red(self.eventos)
        self.ajustes = leer_json(ARCHIVO_AJUSTES, {})
        self.conectado = False
        self.foto = None
        self.ultimo_cuadro = None
        self.caja = (0, 0, 0, 0)
        self.redibujar = False
        self.teclas_abajo = {}
        self.mov_pendiente = None
        self.mov_programado = False
        self.rueda_acum = 0.0
        self.cuadros = 0
        self.t_fps = time.monotonic()
        self.lbl_msg = None
        self.protocol("WM_DELETE_WINDOW", self.al_cerrar)
        self.mostrar_conexion()
        self.after(15, self.bucle)

    # ---- utilidades
    def limpiar(self):
        for w in self.winfo_children():
            w.destroy()
        self.lbl_msg = None

    def mensaje(self, texto, error=False):
        if self.lbl_msg is not None and self.lbl_msg.winfo_exists():
            self.lbl_msg.configure(text=texto, foreground="#c00" if error else "#333")

    def en_segundo_plano(self, coro, ok, err):
        fut = self.red.ejecutar(coro)

        def revisar():
            if not fut.done():
                self.after(30, revisar)
                return
            try:
                resultado = fut.result()
            except Exception as e:
                err(e)
            else:
                ok(resultado)

        self.after(30, revisar)

    # ---- pantalla de conexión
    def mostrar_conexion(self):
        self.limpiar()
        self.title("Acceso Remoto — Cliente")
        marco = ttk.Frame(self, padding=30)
        marco.place(relx=0.5, rely=0.45, anchor="center")
        ttk.Label(marco, text="Acceso Remoto", font=("Segoe UI", 18, "bold")).grid(
            row=0, column=0, columnspan=2, pady=(0, 20))

        self.v_host = tk.StringVar(value=self.ajustes.get("host", ""))
        self.v_puerto = tk.StringVar(value=str(self.ajustes.get("puerto", P.PUERTO_DEFECTO)))
        self.v_pass = tk.StringVar()
        campos = (("Equipo (IP o nombre):", self.v_host, ""),
                  ("Puerto:", self.v_puerto, ""),
                  ("Contraseña:", self.v_pass, "•"))
        entradas = []
        for i, (texto, var, oculto) in enumerate(campos, start=1):
            ttk.Label(marco, text=texto).grid(row=i, column=0, sticky="e", padx=(0, 8), pady=4)
            e = ttk.Entry(marco, textvariable=var, width=30, show=oculto)
            e.grid(row=i, column=1, sticky="w", pady=4)
            e.bind("<Return>", lambda _e: self.conectar())
            entradas.append(e)

        self.btn_conectar = ttk.Button(marco, text="Conectar", command=self.conectar)
        self.btn_conectar.grid(row=4, column=0, columnspan=2, pady=(16, 6))
        self.lbl_msg = ttk.Label(marco, text="", wraplength=340, justify="center")
        self.lbl_msg.grid(row=5, column=0, columnspan=2)
        (entradas[2] if self.v_host.get() else entradas[0]).focus_set()

    def conectar(self):
        host = self.v_host.get().strip()
        password = self.v_pass.get()
        try:
            puerto = int(self.v_puerto.get())
        except ValueError:
            self.mensaje("Puerto inválido", error=True)
            return
        if not host or not password:
            self.mensaje("Completá equipo y contraseña", error=True)
            return
        self.btn_conectar.state(["disabled"])
        self.mensaje("Conectando…")
        self.en_segundo_plano(
            self.red.abrir(host, puerto),
            lambda fp: self._verificar_huella(host, puerto, password, fp),
            self._error_conexion)

    def _verificar_huella(self, host, puerto, password, fp):
        clave = f"{host}:{puerto}"
        conocida = leer_json(ARCHIVO_HOSTS, {}).get(clave)
        if conocida is None:
            ok = messagebox.askyesno(
                "Equipo nuevo",
                f"Es la primera vez que te conectás a {clave}.\n\n"
                f"Huella SHA-256 del certificado:\n{fp}\n\n"
                "Comparala con la que muestra la consola del servidor.\n¿Confiar y continuar?",
                parent=self)
        elif conocida != fp:
            ok = messagebox.askyesno(
                "¡ATENCIÓN! La huella cambió",
                f"La huella del certificado de {clave} NO coincide con la guardada.\n\n"
                f"Guardada:\n{conocida}\n\nActual:\n{fp}\n\n"
                "Puede ser que se haya regenerado el certificado del servidor, o que alguien "
                "esté interceptando la conexión.\n\n¿Confiar en la nueva huella?",
                icon="warning", default="no", parent=self)
        else:
            ok = True
        if not ok:
            self.red.cerrar()
            self._error_conexion(None, "Conexión cancelada")
            return
        self.mensaje("Autenticando…")
        self.en_segundo_plano(
            self.red.autenticar(password),
            lambda info: self._conectado(host, puerto, fp, info),
            self._error_conexion)

    def _error_conexion(self, exc, texto=None):
        if texto is None:
            if isinstance(exc, ErrorAutenticacion):
                texto = str(exc)
            elif isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
                texto = "Tiempo de espera agotado. ¿El equipo está encendido y accesible?"
            elif isinstance(exc, ConnectionRefusedError):
                texto = "Conexión rechazada. ¿Está corriendo el servidor? ¿El firewall permite el puerto?"
            elif isinstance(exc, socket.gaierror):
                texto = "No se pudo resolver el nombre del equipo."
            elif isinstance(exc, ssl.SSLError):
                texto = f"Error TLS: {exc}"
            elif isinstance(exc, asyncio.IncompleteReadError):
                texto = "El servidor cerró la conexión."
            else:
                texto = f"Error: {exc}"
        self.mensaje(texto, error=True)
        if self.btn_conectar.winfo_exists():
            self.btn_conectar.state(["!disabled"])

    def _conectado(self, host, puerto, fp, info):
        hosts = leer_json(ARCHIVO_HOSTS, {})
        hosts[f"{host}:{puerto}"] = fp
        escribir_json(ARCHIVO_HOSTS, hosts)
        self.ajustes.update(host=host, puerto=puerto)
        escribir_json(ARCHIVO_AJUSTES, self.ajustes)
        self.conectado = True
        self.ultimo_cuadro = None
        self.caja = (0, 0, 0, 0)
        self.title(f"Acceso Remoto — {info.get('host', host)} ({host})")
        self.mostrar_visor(info)

    # ---- visor
    def mostrar_visor(self, info):
        self.limpiar()
        barra = ttk.Frame(self, padding=(6, 4))
        barra.pack(side="top", fill="x")

        self.monitores = info.get("monitores", [])
        etiquetas = [("Todas las pantallas" if m["indice"] == 0 else f"Monitor {m['indice']}")
                     + f" ({m['ancho']}x{m['alto']})" for m in self.monitores]

        def combo(texto, valores, actual, ancho):
            ttk.Label(barra, text=texto).pack(side="left", padx=(8, 2))
            cb = ttk.Combobox(barra, values=valores, state="readonly", width=ancho)
            cb.set(actual)
            cb.pack(side="left")
            cb.bind("<<ComboboxSelected>>", self.enviar_config)
            return cb

        actual = info.get("monitor", 1)
        self.cb_mon = combo("Pantalla:", etiquetas,
                            etiquetas[actual] if actual < len(etiquetas) else "", 26)
        self.cb_cal = combo("Calidad:", ["30", "50", "60", "70", "85", "95"],
                            str(info.get("calidad", 60)), 4)
        self.cb_esc = combo("Escala:", ["100%", "75%", "50%", "35%"],
                            f"{int(round(float(info.get('escala', 1)) * 100))}%", 5)
        self.cb_fps = combo("FPS:", ["5", "10", "15", "20", "25", "30"],
                            str(info.get("fps", 15)), 4)

        ttk.Button(barra, text="Desconectar", command=self.desconectar).pack(side="right", padx=2)
        self.btn_archivo = ttk.Button(barra, text="Enviar archivo…", command=self.enviar_archivo)
        self.btn_archivo.pack(side="right", padx=2)
        ttk.Button(barra, text="Escribir portapapeles",
                   command=self.escribir_portapapeles).pack(side="right", padx=2)

        estado = ttk.Frame(self, padding=(8, 2))
        estado.pack(side="bottom", fill="x")
        self.lbl_info = ttk.Label(estado, text=f"Conectado a {info.get('host', '')}")
        self.lbl_info.pack(side="left")
        self.lbl_msg = ttk.Label(estado, text="Hacé clic en la pantalla para darle el foco al teclado")
        self.lbl_msg.pack(side="right")

        c = self.lienzo = tk.Canvas(self, bg="black", highlightthickness=0, takefocus=1)
        c.pack(side="top", fill="both", expand=True)
        self.item_img = c.create_image(0, 0, anchor="nw")

        c.bind("<Configure>", lambda _e: setattr(self, "redibujar", True))
        c.bind("<Motion>", self.al_mover)
        botones = ((1, "left"), (2, "right"), (3, "middle")) if ES_MAC else \
                  ((1, "left"), (2, "middle"), (3, "right"))
        for n, nombre in botones:
            c.bind(f"<ButtonPress-{n}>", lambda e, b=nombre: self.al_boton(e, b, True))
            c.bind(f"<ButtonRelease-{n}>", lambda e, b=nombre: self.al_boton(e, b, False))
        c.bind("<MouseWheel>", self.al_rueda)
        c.bind("<Button-4>", lambda _e: self.enviar_entrada({"t": "wh", "dx": 0, "dy": 1}))
        c.bind("<Button-5>", lambda _e: self.enviar_entrada({"t": "wh", "dx": 0, "dy": -1}))
        c.bind("<KeyPress>", lambda e: self.al_tecla(e, True))
        c.bind("<KeyRelease>", lambda e: self.al_tecla(e, False))
        c.bind("<FocusOut>", self.al_perder_foco)
        c.focus_set()

    def enviar_config(self, _e=None):
        i = self.cb_mon.current()
        cfg = {
            "monitor": self.monitores[i]["indice"] if i >= 0 else 1,
            "calidad": int(self.cb_cal.get()),
            "escala": int(self.cb_esc.get().rstrip("%")) / 100,
            "fps": int(self.cb_fps.get()),
        }
        self.red.enviar(P.MSG_CONFIG, cfg)
        self.lienzo.focus_set()

    def enviar_entrada(self, ev):
        if self.conectado:
            self.red.enviar(P.MSG_INPUT, ev)

    def a_remoto(self, x, y, recortar=False):
        ox, oy, w, h = self.caja
        if w <= 0 or h <= 0:
            return None
        rx, ry = (x - ox) / w, (y - oy) / h
        if recortar:
            rx, ry = min(max(rx, 0.0), 1.0), min(max(ry, 0.0), 1.0)
        elif not (0 <= rx <= 1 and 0 <= ry <= 1):
            return None
        return round(rx, 5), round(ry, 5)

    def al_mover(self, e):
        arrastrando = bool(e.state & 0x0700)  # algún botón presionado
        p = self.a_remoto(e.x, e.y, recortar=arrastrando)
        if p is None:
            return
        self.mov_pendiente = p
        if not self.mov_programado:  # máx. ~60 movimientos por segundo
            self.mov_programado = True
            self.after(16, self._enviar_movimiento)

    def _enviar_movimiento(self):
        self.mov_programado = False
        if self.mov_pendiente:
            x, y = self.mov_pendiente
            self.mov_pendiente = None
            self.enviar_entrada({"t": "mv", "x": x, "y": y})

    def al_boton(self, e, boton, abajo):
        self.lienzo.focus_set()
        p = self.a_remoto(e.x, e.y, recortar=not abajo)
        if p is None:
            return
        self.mov_pendiente = None
        self.enviar_entrada({"t": "md" if abajo else "mu", "b": boton, "x": p[0], "y": p[1]})

    def al_rueda(self, e):
        if ES_MAC:
            pasos = e.delta
        else:
            self.rueda_acum += e.delta / 120  # touchpads envían fracciones
            pasos = int(self.rueda_acum)
            self.rueda_acum -= pasos
        if pasos:
            self.enviar_entrada({"t": "wh", "dx": 0, "dy": pasos})

    def al_tecla(self, e, abajo):
        if not self.conectado:
            return "break"
        if abajo:
            ev = {"vk": e.keycode if ES_WINDOWS else 0, "ks": e.keysym,
                  "ch": e.char if len(e.char) == 1 else ""}
            self.teclas_abajo[e.keycode] = ev
            self.enviar_entrada({"t": "kd", **ev})
        else:
            # Se suelta exactamente la misma tecla que se presionó (evita teclas trabadas)
            ev = self.teclas_abajo.pop(e.keycode, None) or {
                "vk": e.keycode if ES_WINDOWS else 0, "ks": e.keysym, "ch": ""}
            self.enviar_entrada({"t": "ku", **ev})
        return "break"  # que Tab, Alt, etc. no actúen sobre la ventana local

    def al_perder_foco(self, _e=None):
        if self.teclas_abajo:
            self.teclas_abajo.clear()
            self.enviar_entrada({"t": "ra"})

    def escribir_portapapeles(self):
        try:
            texto = self.clipboard_get()
        except tk.TclError:
            self.mensaje("El portapapeles no contiene texto", error=True)
            return
        if len(texto) > 10000:
            if not messagebox.askyesno("Texto largo", "Se enviarán solo los primeros 10.000 "
                                       "caracteres. ¿Continuar?", parent=self):
                return
            texto = texto[:10000]
        self.enviar_entrada({"t": "type", "text": texto})
        self.mensaje(f"Escribiendo {len(texto)} caracteres en el remoto…")
        self.lienzo.focus_set()

    def enviar_archivo(self):
        ruta = filedialog.askopenfilename(parent=self, title="Elegí el archivo a enviar")
        self.lienzo.focus_set()
        if not ruta:
            return
        self.btn_archivo.state(["disabled"])

        def fin(_r=None):
            if self.conectado and self.btn_archivo.winfo_exists():
                self.btn_archivo.state(["!disabled"])

        def error(exc):
            self.mensaje(f"Error al enviar: {exc}", error=True)
            fin()

        self.en_segundo_plano(self.red.enviar_archivo(ruta), fin, error)

    def desconectar(self):
        self.conectado = False
        self.red.cerrar()
        self.mostrar_conexion()

    def al_cerrar(self):
        if self.conectado and not messagebox.askyesno(
                "Salir", "¿Cerrar la sesión remota y salir?", parent=self):
            return
        self.conectado = False
        self.red.cerrar()
        self.after(150, self.destroy)

    # ---- bucle de la interfaz
    def bucle(self):
        try:
            while True:
                try:
                    ev = self.eventos.get_nowait()
                except queue.Empty:
                    break
                self.procesar_evento(ev)
            if self.conectado:
                cuadro = self.red.tomar_cuadro()
                if cuadro is not None:
                    self.ultimo_cuadro = cuadro
                    self.dibujar()
                    self.cuadros += 1
                elif self.redibujar and self.ultimo_cuadro:
                    self.dibujar()
                ahora = time.monotonic()
                if ahora - self.t_fps >= 1 and self.lbl_info.winfo_exists():
                    fps = self.cuadros / (ahora - self.t_fps)
                    texto = self.lbl_info.cget("text").split("  ·")[0]
                    self.lbl_info.configure(text=f"{texto}  ·  {fps:.1f} cuadros/s")
                    self.cuadros, self.t_fps = 0, ahora
        except Exception as e:  # nunca cortar el bucle de la interfaz
            print("Error en la interfaz:", e, file=sys.stderr)
        finally:
            self.after(15, self.bucle)

    def procesar_evento(self, ev):
        tipo = ev[0]
        if tipo == "info":
            self.mensaje(ev[1].get("msg", ""), error=bool(ev[1].get("error")))
        elif tipo == "progreso":
            enviados, total = ev[1], ev[2]
            pct = 100 * enviados / total if total else 100
            self.mensaje(f"Enviando archivo… {pct:.0f}%")
        elif tipo == "cerrada" and self.conectado:
            self.conectado = False
            self.teclas_abajo.clear()
            self.mostrar_conexion()
            messagebox.showwarning("Desconectado", ev[1], parent=self)

    def dibujar(self):
        self.redibujar = False
        cw, ch = self.lienzo.winfo_width(), self.lienzo.winfo_height()
        if cw < 2 or ch < 2:
            return
        img = Image.open(io.BytesIO(self.ultimo_cuadro))
        img.load()
        iw, ih = img.size
        r = min(cw / iw, ch / ih)
        dw, dh = max(1, int(iw * r)), max(1, int(ih * r))
        if (dw, dh) != (iw, ih):
            img = img.resize((dw, dh), Image.BILINEAR)
        self.foto = ImageTk.PhotoImage(img)
        ox, oy = (cw - dw) // 2, (ch - dh) // 2
        self.lienzo.coords(self.item_img, ox, oy)
        self.lienzo.itemconfigure(self.item_img, image=self.foto)
        self.caja = (ox, oy, dw, dh)


if __name__ == "__main__":
    App().mainloop()
