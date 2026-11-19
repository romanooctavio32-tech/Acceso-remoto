#!/usr/bin/env python3
"""
Servidor de Acceso Remoto — se ejecuta en la PC que se quiere controlar.

  * Transmite la pantalla como JPEG (solo cuando cambia) por un canal TLS.
  * Recibe eventos de mouse y teclado y los reproduce en el equipo.
  * Recibe archivos y los guarda en Descargas\\AccesoRemoto.
  * Autenticación por contraseña con desafío HMAC (la contraseña nunca viaja).
  * Bloqueo temporal por IP tras varios intentos fallidos.
  * Registro de accesos en accesos_remoto.log.

Uso:
    python servidor.py                     # inicia (la 1ª vez pide contraseña)
    python servidor.py --cambiar-password  # cambia la contraseña
    python servidor.py --puerto 6000       # puerto distinto (solo esta ejecución)
"""
import argparse
import asyncio
import ctypes
import datetime
import getpass
import hashlib
import hmac
import io
import json
import logging
import re
import secrets
import socket
import ssl
import sys
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ES_WINDOWS = sys.platform == "win32"


def activar_dpi():
    """Sin esto, en pantallas con escalado (125 %, 150 %) las coordenadas no coinciden."""
    if not ES_WINDOWS:
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


activar_dpi()

import mss  # noqa: E402
from PIL import Image  # noqa: E402
from pynput.keyboard import Controller as Teclado, Key, KeyCode  # noqa: E402
from pynput.mouse import Button, Controller as Mouse  # noqa: E402

import protocolo as P  # noqa: E402

if getattr(sys, "frozen", False):
    BASE = Path(sys.executable).resolve().parent
else:
    BASE = Path(__file__).resolve().parent

ARCHIVO_CONFIG = BASE / "config_servidor.json"
ARCHIVO_CERT = BASE / "servidor_cert.pem"
ARCHIVO_CLAVE_TLS = BASE / "servidor_clave.pem"
ARCHIVO_LOG = BASE / "accesos_remoto.log"
EQUIPO = socket.gethostname()

DEFAULTS = {
    "host": "0.0.0.0",
    "puerto": P.PUERTO_DEFECTO,
    "fps": 15,
    "calidad": 60,
    "escala": 1.0,
    "carpeta_archivos": str(Path.home() / "Downloads" / "AccesoRemoto"),
    "max_archivo_mb": 2048,
    "intentos_max": 5,
    "bloqueo_minutos": 5,
}

BOTONES = {"left": Button.left, "right": Button.right, "middle": Button.middle}

# Códigos virtuales de Windows -> nombre de tecla en pynput (las teclas
# "extendidas" como flechas necesitan el objeto Key para enviarse bien).
VK_A_TECLA = {
    8: "backspace", 9: "tab", 13: "enter", 16: "shift", 17: "ctrl", 18: "alt",
    19: "pause", 20: "caps_lock", 27: "esc", 32: "space", 33: "page_up",
    34: "page_down", 35: "end", 36: "home", 37: "left", 38: "up", 39: "right",
    40: "down", 44: "print_screen", 45: "insert", 46: "delete", 91: "cmd",
    92: "cmd_r", 93: "menu", 144: "num_lock", 145: "scroll_lock",
    **{112 + i: f"f{i + 1}" for i in range(12)},
}

# keysym de Tk -> nombre en pynput (para clientes que no son Windows)
KEYSYM_A_TECLA = {
    "Return": "enter", "KP_Enter": "enter", "BackSpace": "backspace", "Tab": "tab",
    "Escape": "esc", "Delete": "delete", "Insert": "insert", "Home": "home",
    "End": "end", "Prior": "page_up", "Next": "page_down", "Left": "left",
    "Right": "right", "Up": "up", "Down": "down", "Shift_L": "shift_l",
    "Shift_R": "shift_r", "Control_L": "ctrl_l", "Control_R": "ctrl_r",
    "Alt_L": "alt_l", "Alt_R": "alt_r", "ISO_Level3_Shift": "alt_gr",
    "Super_L": "cmd", "Super_R": "cmd_r", "Caps_Lock": "caps_lock",
    "space": "space", "Menu": "menu", "Print": "print_screen", "Pause": "pause",
    "Num_Lock": "num_lock", "Scroll_Lock": "scroll_lock",
    **{f"F{i}": f"f{i}" for i in range(1, 13)},
}

log = logging.getLogger("acceso_remoto")


# ----------------------------------------------------------------- utilidades
def configurar_log():
    fmt = logging.Formatter("%(asctime)s  %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")
    log.setLevel(logging.INFO)
    consola = logging.StreamHandler(sys.stdout)
    consola.setFormatter(fmt)
    archivo = logging.FileHandler(ARCHIVO_LOG, encoding="utf-8")
    archivo.setFormatter(fmt)
    log.addHandler(consola)
    log.addHandler(archivo)


def titulo_consola(texto):
    if ES_WINDOWS:
        try:
            ctypes.windll.kernel32.SetConsoleTitleW(texto)
        except Exception:
            pass


def cargar_config():
    cfg = dict(DEFAULTS)
    if ARCHIVO_CONFIG.exists():
        cfg.update(json.loads(ARCHIVO_CONFIG.read_text("utf-8")))
    return cfg


def guardar_config(cfg):
    ARCHIVO_CONFIG.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), "utf-8")


def definir_password(cfg):
    print("\n=== Configurar contraseña de acceso ===")
    while True:
        p1 = getpass.getpass("Nueva contraseña (mínimo 8 caracteres): ")
        if len(p1) < 8:
            print("  Demasiado corta.")
            continue
        if getpass.getpass("Repetir contraseña: ") != p1:
            print("  No coinciden.")
            continue
        break
    salt = secrets.token_bytes(16)
    clave = hashlib.pbkdf2_hmac("sha256", p1.encode("utf-8"), salt, P.ITERACIONES_PBKDF2)
    cfg["salt"] = salt.hex()
    cfg["iteraciones"] = P.ITERACIONES_PBKDF2
    cfg["clave"] = clave.hex()
    print("Contraseña guardada (solo se almacena un hash derivado).\n")


def asegurar_certificado() -> str:
    """Genera un certificado autofirmado la primera vez y devuelve su huella."""
    if not (ARCHIVO_CERT.exists() and ARCHIVO_CLAVE_TLS.exists()):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        log.info("Generando certificado TLS autofirmado…")
        clave = ec.generate_private_key(ec.SECP256R1())
        nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, EQUIPO)])
        ahora = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder()
                .subject_name(nombre).issuer_name(nombre)
                .public_key(clave.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(ahora - datetime.timedelta(days=1))
                .not_valid_after(ahora + datetime.timedelta(days=3650))
                .sign(clave, hashes.SHA256()))
        ARCHIVO_CLAVE_TLS.write_bytes(clave.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        ARCHIVO_CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    der = ssl.PEM_cert_to_DER_cert(ARCHIVO_CERT.read_text("ascii"))
    return P.huella(der)


def ips_locales():
    ips = set()
    try:
        for info in socket.getaddrinfo(EQUIPO, None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # no envía datos, solo elige la interfaz
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return sorted(ip for ip in ips if not ip.startswith("127."))


def nombre_unico(carpeta: Path, nombre: str) -> Path:
    destino = carpeta / nombre
    n = 1
    while destino.exists():
        destino = carpeta / f"{Path(nombre).stem} ({n}){Path(nombre).suffix}"
        n += 1
    return destino


# --------------------------------------------------------------------- sesión
class Sesion:
    def __init__(self, cfg, reader, writer, ip, cliente):
        self.cfg = cfg
        self.reader = reader
        self.writer = writer
        self.ip = ip
        self.cliente = cliente
        self.loop = asyncio.get_running_loop()
        # mss debe usarse siempre desde el mismo hilo
        self.hilo_captura = ThreadPoolExecutor(max_workers=1, thread_name_prefix="captura")
        self._sct = None
        self.monitor = 1
        self.n_monitores = 2
        self.calidad = int(cfg["calidad"])
        self.fps = int(cfg["fps"])
        self.escala = float(cfg["escala"])
        self.forzar = True
        self.geom = (0, 0, 1, 1)
        self.mouse = Mouse()
        self.teclado = Teclado()
        self.teclas = set()
        self.botones = set()
        self.archivo = None
        self.archivo_ruta = None
        self.archivo_esperado = 0
        self.archivo_recibido = 0
        self.tareas = set()

    def enviar(self, tipo, payload=b""):
        if not self.writer.is_closing():
            self.writer.write(P.empaquetar(tipo, payload))

    # ---- captura (corre en el hilo de captura)
    def _sct_hilo(self):
        if self._sct is None:
            self._sct = getattr(mss, "MSS", mss.mss)()  # mss >= 10 usa mss.MSS
        return self._sct

    def _monitores(self):
        sct = self._sct_hilo()
        return [{"indice": i, "ancho": m["width"], "alto": m["height"],
                 "x": m["left"], "y": m["top"]} for i, m in enumerate(sct.monitors)]

    def _capturar(self, monitor, calidad, escala, crc_previo, forzar):
        sct = self._sct_hilo()
        mons = sct.monitors
        mon = mons[monitor] if monitor < len(mons) else mons[min(1, len(mons) - 1)]
        geom = (mon["left"], mon["top"], mon["width"], mon["height"])
        shot = sct.grab(mon)
        crc = zlib.crc32(shot.raw)
        if crc == crc_previo and not forzar:
            return crc, geom, None
        img = Image.frombytes("RGB", shot.size, shot.bgra, "raw", "BGRX")
        if escala < 0.999:
            img = img.resize((max(1, int(img.width * escala)), max(1, int(img.height * escala))),
                             Image.BILINEAR)
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=calidad)
        return crc, geom, buf.getvalue()

    def _cerrar_sct(self):
        if self._sct is not None:
            self._sct.close()
            self._sct = None

    async def _transmitir(self):
        crc = None
        while True:
            t0 = self.loop.time()
            try:
                forzar, self.forzar = self.forzar, False
                crc, self.geom, jpeg = await self.loop.run_in_executor(
                    self.hilo_captura, self._capturar,
                    self.monitor, self.calidad, self.escala, crc, forzar)
                if jpeg:
                    self.enviar(P.MSG_FRAME, jpeg)
                    await self.writer.drain()  # se adapta al ancho de banda disponible
            except asyncio.CancelledError:
                raise
            except (ConnectionError, OSError) as e:
                if self.writer.is_closing():
                    return
                # Pantalla bloqueada / UAC: el escritorio seguro no se puede capturar
                log.warning("No se pudo capturar la pantalla: %s", e)
                await asyncio.sleep(1)
                continue
            except Exception as e:
                log.warning("Error de captura: %s", e)
                await asyncio.sleep(1)
                continue
            await asyncio.sleep(max(0.0, 1 / self.fps - (self.loop.time() - t0)))

    # ---- entrada
    def _absoluto(self, ev):
        izq, arriba, ancho, alto = self.geom
        x = min(max(float(ev.get("x", 0)), 0.0), 1.0)
        y = min(max(float(ev.get("y", 0)), 0.0), 1.0)
        return int(izq + x * (ancho - 1)), int(arriba + y * (alto - 1))

    @staticmethod
    def _resolver_tecla(ev):
        vk = ev.get("vk") or 0
        ks = str(ev.get("ks") or "")
        ch = str(ev.get("ch") or "")
        if ES_WINDOWS and vk:
            nombre = VK_A_TECLA.get(int(vk))
            tecla = getattr(Key, nombre, None) if nombre else None
            return tecla or KeyCode.from_vk(int(vk))
        nombre = KEYSYM_A_TECLA.get(ks)
        if nombre and getattr(Key, nombre, None):
            return getattr(Key, nombre)
        if len(ch) == 1 and ch.isprintable():
            return KeyCode.from_char(ch)
        if len(ks) == 1:
            return KeyCode.from_char(ks)
        return None

    def soltar_todo(self):
        for t in list(self.teclas):
            try:
                self.teclado.release(t)
            except Exception:
                pass
        for b in list(self.botones):
            try:
                self.mouse.release(b)
            except Exception:
                pass
        self.teclas.clear()
        self.botones.clear()

    def _entrada(self, ev):
        t = ev.get("t")
        if t == "mv":
            self.mouse.position = self._absoluto(ev)
        elif t in ("md", "mu"):
            if "x" in ev:
                self.mouse.position = self._absoluto(ev)
            boton = BOTONES.get(ev.get("b"))
            if boton is None:
                return
            if t == "md":
                self.mouse.press(boton)
                self.botones.add(boton)
            else:
                self.mouse.release(boton)
                self.botones.discard(boton)
        elif t == "wh":
            self.mouse.scroll(int(ev.get("dx", 0)), int(ev.get("dy", 0)))
        elif t in ("kd", "ku"):
            tecla = self._resolver_tecla(ev)
            if tecla is None:
                return
            if t == "kd":
                self.teclado.press(tecla)
                self.teclas.add(tecla)
            else:
                self.teclado.release(tecla)
                self.teclas.discard(tecla)
        elif t == "ra":
            self.soltar_todo()
        elif t == "type":
            texto = str(ev.get("text", ""))[:10000]
            tarea = asyncio.ensure_future(asyncio.to_thread(self.teclado.type, texto))
            self.tareas.add(tarea)
            tarea.add_done_callback(self.tareas.discard)

    def _config(self, d):
        if "monitor" in d and 0 <= int(d["monitor"]) < self.n_monitores:
            self.monitor = int(d["monitor"])
        if "calidad" in d:
            self.calidad = max(10, min(95, int(d["calidad"])))
        if "fps" in d:
            self.fps = max(1, min(30, int(d["fps"])))
        if "escala" in d:
            self.escala = max(0.25, min(1.0, float(d["escala"])))
        self.forzar = True
        log.info("Ajustes: monitor=%s calidad=%s fps=%s escala=%.0f%%",
                 self.monitor, self.calidad, self.fps, self.escala * 100)

    # ---- archivos
    def _archivo_inicio(self, d):
        self._archivo_abortar()
        nombre = Path(str(d.get("name", "archivo"))).name
        nombre = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", nombre).strip(" .") or "archivo"
        tam = int(d.get("size", 0))
        if tam > int(self.cfg["max_archivo_mb"]) * 1024 * 1024:
            self.enviar(P.MSG_INFO, {"msg": f"Archivo rechazado: supera {self.cfg['max_archivo_mb']} MB",
                                     "error": True})
            return
        carpeta = Path(self.cfg["carpeta_archivos"])
        carpeta.mkdir(parents=True, exist_ok=True)
        self.archivo_ruta = nombre_unico(carpeta, nombre)
        self.archivo = open(self.archivo_ruta, "wb")
        self.archivo_esperado = tam
        self.archivo_recibido = 0

    def _archivo_bloque(self, datos):
        if not self.archivo:
            return
        self.archivo_recibido += len(datos)
        if self.archivo_recibido > self.archivo_esperado:
            self._archivo_abortar()
            self.enviar(P.MSG_INFO, {"msg": "Archivo rechazado: tamaño incorrecto", "error": True})
            return
        self.archivo.write(datos)

    def _archivo_fin(self):
        if not self.archivo:
            return
        self.archivo.close()
        self.archivo = None
        if self.archivo_recibido == self.archivo_esperado:
            log.info("Archivo recibido de %s: %s (%d bytes)", self.ip, self.archivo_ruta,
                     self.archivo_recibido)
            self.enviar(P.MSG_INFO, {"msg": f"Archivo guardado en el remoto: {self.archivo_ruta}"})
        else:
            self.archivo_ruta.unlink(missing_ok=True)
            self.enviar(P.MSG_INFO, {"msg": "Archivo incompleto, descartado", "error": True})

    def _archivo_abortar(self):
        if self.archivo:
            self.archivo.close()
            self.archivo = None
            self.archivo_ruta.unlink(missing_ok=True)

    # ---- ciclo principal
    async def ejecutar(self):
        monitores = await self.loop.run_in_executor(self.hilo_captura, self._monitores)
        self.n_monitores = len(monitores)
        self.monitor = 1 if self.n_monitores > 1 else 0
        m = monitores[self.monitor]
        self.geom = (m["x"], m["y"], m["ancho"], m["alto"])
        self.enviar(P.MSG_AUTH_OK, {
            "host": EQUIPO, "monitores": monitores, "monitor": self.monitor,
            "calidad": self.calidad, "fps": self.fps, "escala": self.escala,
        })
        await self.writer.drain()
        transmision = asyncio.create_task(self._transmitir())
        try:
            while True:
                tipo, datos = await P.leer(self.reader)
                try:
                    if tipo == P.MSG_INPUT:
                        self._entrada(P.a_json(datos))
                    elif tipo == P.MSG_CONFIG:
                        self._config(P.a_json(datos))
                    elif tipo == P.MSG_FILE_START:
                        self._archivo_inicio(P.a_json(datos))
                    elif tipo == P.MSG_FILE_CHUNK:
                        self._archivo_bloque(datos)
                    elif tipo == P.MSG_FILE_END:
                        self._archivo_fin()
                except (P.ErrorProtocolo, ValueError, TypeError) as e:
                    log.warning("Mensaje inválido de %s: %s", self.ip, e)
                except OSError as e:
                    log.warning("Error procesando mensaje: %s", e)
                    self.enviar(P.MSG_INFO, {"msg": f"Error en el remoto: {e}", "error": True})
        finally:
            transmision.cancel()
            await asyncio.gather(transmision, return_exceptions=True)
            self.soltar_todo()
            self._archivo_abortar()
            self.hilo_captura.submit(self._cerrar_sct)
            self.hilo_captura.shutdown(wait=False)


# ------------------------------------------------------------------- servidor
class Servidor:
    def __init__(self, cfg):
        self.cfg = cfg
        self.fallos = {}
        self.activa = None

    def _bloqueado(self, ip):
        ahora = time.monotonic()
        ventana = float(self.cfg["bloqueo_minutos"]) * 60
        recientes = [t for t in self.fallos.get(ip, []) if ahora - t < ventana]
        self.fallos[ip] = recientes
        return len(recientes) >= int(self.cfg["intentos_max"])

    async def atender(self, reader, writer):
        ip = (writer.get_extra_info("peername") or ("?",))[0]
        sock = writer.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except OSError:
                pass
        try:
            if self._bloqueado(ip):
                log.warning("Conexión rechazada de %s (bloqueada por intentos fallidos)", ip)
                writer.write(P.empaquetar(P.MSG_AUTH_FAIL, {
                    "error": "Demasiados intentos fallidos. Probá de nuevo más tarde."}))
                await writer.drain()
                return

            nonce = secrets.token_bytes(32)
            writer.write(P.empaquetar(P.MSG_HELLO, {
                "version": P.VERSION, "host": EQUIPO, "salt": self.cfg["salt"],
                "iter": self.cfg["iteraciones"], "nonce": nonce.hex()}))
            await writer.drain()

            # Margen amplio: el usuario puede estar verificando la huella
            tipo, datos = await asyncio.wait_for(P.leer(reader), timeout=120)
            if tipo != P.MSG_AUTH:
                return
            auth = P.a_json(datos)
            cliente = str(auth.get("equipo", "?"))[:64]
            esperado = hmac.new(bytes.fromhex(self.cfg["clave"]), nonce, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(esperado, str(auth.get("resp", ""))):
                self.fallos.setdefault(ip, []).append(time.monotonic())
                log.warning("Contraseña incorrecta desde %s (%s)", ip, cliente)
                await asyncio.sleep(1)
                writer.write(P.empaquetar(P.MSG_AUTH_FAIL, {"error": "Contraseña incorrecta"}))
                await writer.drain()
                return
            if self.activa:
                writer.write(P.empaquetar(P.MSG_AUTH_FAIL, {
                    "error": f"Ya hay una sesión activa desde {self.activa}"}))
                await writer.drain()
                return

            self.fallos.pop(ip, None)
            self.activa = f"{ip} ({cliente})"
            log.info(">>> SESIÓN INICIADA desde %s", self.activa)
            titulo_consola(f"Acceso Remoto - SESIÓN ACTIVA desde {self.activa}")
            try:
                await Sesion(self.cfg, reader, writer, ip, cliente).ejecutar()
            finally:
                log.info("<<< SESIÓN FINALIZADA (%s)", self.activa)
                self.activa = None
                titulo_consola("Acceso Remoto - esperando conexiones")
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError,
                ssl.SSLError, P.ErrorProtocolo):
            pass
        except Exception:
            log.exception("Error inesperado con %s", ip)
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 3)
            except Exception:
                pass


async def servir(cfg, huella_cert):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(ARCHIVO_CERT, ARCHIVO_CLAVE_TLS)
    srv = Servidor(cfg)
    server = await asyncio.start_server(srv.atender, cfg["host"], int(cfg["puerto"]),
                                        ssl=ctx, ssl_handshake_timeout=15)
    print("=" * 66)
    print(f"  ACCESO REMOTO — servidor activo en {EQUIPO}")
    print(f"  Escuchando en {cfg['host']}:{cfg['puerto']}")
    for ip in ips_locales():
        print(f"    IP de este equipo: {ip}")
    print("  Huella SHA-256 del certificado (verificala en el cliente):")
    print(f"    {huella_cert}")
    print("  Cerrá esta ventana o presioná Ctrl+C para detener el servidor.")
    print("=" * 66)
    titulo_consola("Acceso Remoto - esperando conexiones")
    async with server:
        await server.serve_forever()


def main():
    ap = argparse.ArgumentParser(description="Servidor de Acceso Remoto")
    ap.add_argument("--cambiar-password", action="store_true", help="definir una nueva contraseña")
    ap.add_argument("--puerto", type=int, help="puerto TCP (solo para esta ejecución)")
    ap.add_argument("--host", help="IP en la que escuchar (por defecto 0.0.0.0)")
    args = ap.parse_args()

    configurar_log()
    cfg = cargar_config()
    if args.cambiar_password or not cfg.get("clave"):
        definir_password(cfg)
    guardar_config(cfg)
    if args.puerto:
        cfg["puerto"] = args.puerto
    if args.host:
        cfg["host"] = args.host

    huella_cert = asegurar_certificado()
    try:
        asyncio.run(servir(cfg, huella_cert))
    except KeyboardInterrupt:
        log.info("Servidor detenido")
    except OSError as e:
        log.error("No se pudo iniciar el servidor: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
