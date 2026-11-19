"""
Protocolo compartido entre el servidor y el cliente de Acceso Remoto.

Cada mensaje viaja dentro de un canal TLS con este formato:

    [4 bytes: largo del payload (big-endian)] [1 byte: tipo] [payload]

Los payloads de control son JSON (UTF-8); los cuadros de pantalla son JPEG
y los bloques de archivo son bytes crudos.
"""
import asyncio
import hashlib
import hmac
import json
import struct

VERSION = 1
PUERTO_DEFECTO = 5950
ITERACIONES_PBKDF2 = 200_000

CABECERA = struct.Struct("!IB")
MAX_MENSAJE = 16 * 1024 * 1024  # 16 MB por mensaje

# Tipos de mensaje
MSG_HELLO = 1        # servidor -> cliente: desafío (salt, nonce, iteraciones)
MSG_AUTH = 2         # cliente  -> servidor: respuesta HMAC al desafío
MSG_AUTH_OK = 3      # servidor -> cliente: acceso concedido + info de monitores
MSG_AUTH_FAIL = 4    # servidor -> cliente: acceso denegado
MSG_FRAME = 5        # servidor -> cliente: cuadro JPEG
MSG_INPUT = 6        # cliente  -> servidor: evento de mouse / teclado
MSG_CONFIG = 7       # cliente  -> servidor: calidad, fps, escala, monitor
MSG_INFO = 8         # servidor -> cliente: mensajes informativos
MSG_FILE_START = 9   # cliente  -> servidor: inicio de archivo {name, size}
MSG_FILE_CHUNK = 10  # cliente  -> servidor: bloque de archivo
MSG_FILE_END = 11    # cliente  -> servidor: fin de archivo


class ErrorProtocolo(Exception):
    pass


def empaquetar(tipo: int, payload=b"") -> bytes:
    if isinstance(payload, (dict, list)):
        payload = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    elif isinstance(payload, str):
        payload = payload.encode("utf-8")
    if len(payload) > MAX_MENSAJE:
        raise ErrorProtocolo("Mensaje demasiado grande")
    return CABECERA.pack(len(payload), tipo) + payload


async def leer(reader: asyncio.StreamReader):
    cabecera = await reader.readexactly(CABECERA.size)
    largo, tipo = CABECERA.unpack(cabecera)
    if largo > MAX_MENSAJE:
        raise ErrorProtocolo(f"Mensaje demasiado grande ({largo} bytes)")
    datos = await reader.readexactly(largo) if largo else b""
    return tipo, datos


def a_json(datos: bytes) -> dict:
    try:
        obj = json.loads(datos.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ErrorProtocolo(f"JSON inválido: {e}") from e
    if not isinstance(obj, dict):
        raise ErrorProtocolo("Se esperaba un objeto JSON")
    return obj


def derivar_clave(password: str, salt_hex: str, iteraciones: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               bytes.fromhex(salt_hex), int(iteraciones))


def respuesta_desafio(clave: bytes, nonce_hex: str) -> str:
    return hmac.new(clave, bytes.fromhex(nonce_hex), hashlib.sha256).hexdigest()


def huella(cert_der: bytes) -> str:
    h = hashlib.sha256(cert_der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))
