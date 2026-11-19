# Acceso Remoto — cliente/servidor en Python

Escritorio remoto liviano: ves la pantalla de otra PC y la controlás con mouse y teclado.

| Parte | Dónde corre | Qué hace |
|---|---|---|
| `servidor.py` | PC a controlar | Captura la pantalla, recibe mouse/teclado/archivos |
| `cliente.py` | PC desde la que controlás | Ventana con la pantalla remota |
| `protocolo.py` | Ambas | Formato de mensajes y autenticación (va junto a los dos) |

## Funciones

- Pantalla en vivo en JPEG; solo se envía cuando cambia, y se adapta al ancho de banda
- Mouse completo (mover, clic izquierdo/derecho/medio, arrastrar, rueda) y teclado
- Selector de monitor (o todos), calidad, escala y FPS en vivo
- **Escribir portapapeles**: tipea en el remoto el texto que copiaste localmente
- **Enviar archivo**: lo guarda en `Descargas\AccesoRemoto` del remoto
- Soporta pantallas con escalado de Windows (125 %, 150 %…)

## Seguridad

- **TLS** (certificado autofirmado que se genera solo la primera vez).
- **Verificación por huella**, como en SSH: el cliente muestra la huella SHA-256 la primera vez y la recuerda. Si cambia, te avisa.
- **Contraseña con desafío HMAC**: la contraseña nunca viaja por la red y el servidor guarda solo un hash PBKDF2 (200.000 iteraciones).
- **Bloqueo por IP**: después de 5 intentos fallidos, la IP queda bloqueada 5 minutos.
- **Una sola sesión a la vez.** El título de la consola del servidor muestra `SESIÓN ACTIVA desde …`.
- **Registro** de conexiones, fallos y archivos en `accesos_remoto.log`.

## Instalación

Hace falta Python 3.9 o superior.

```bat
pip install -r requirements.txt
```

### En la PC a controlar (servidor)

```bat
python servidor.py
```

La primera vez te pide una contraseña. Después muestra las IP del equipo y la **huella del certificado**. Para cambiar la contraseña: `python servidor.py --cambiar-password`.

Abrí el puerto en el firewall de Windows (en una consola como administrador):

```bat
netsh advfirewall firewall add rule name="Acceso Remoto" dir=in action=allow protocol=TCP localport=5950
```

### En tu PC (cliente)

```bat
python cliente.py
```

Ingresá la IP, el puerto (5950) y la contraseña. La primera vez compará la huella con la que muestra el servidor.

## Configuración (`config_servidor.json`)

| Clave | Por defecto | Descripción |
|---|---|---|
| `host` | `0.0.0.0` | IP en la que escucha (usá la IP de la VPN para limitarlo a esa red) |
| `puerto` | `5950` | Puerto TCP |
| `fps` / `calidad` / `escala` | 15 / 60 / 1.0 | Valores iniciales (el cliente los cambia en vivo) |
| `carpeta_archivos` | `~\Downloads\AccesoRemoto` | Dónde se guardan los archivos recibidos |
| `max_archivo_mb` | 2048 | Tamaño máximo por archivo |
| `intentos_max` / `bloqueo_minutos` | 5 / 5 | Política de bloqueo |

`salt`, `iteraciones` y `clave` los genera `--cambiar-password`. No los edites a mano.

## Uso fuera de la red local

No expongas el puerto directo a Internet. Conectate por VPN (WireGuard, Tailscale, ZeroTier o la VPN de la empresa) y usá la IP de la VPN.

## Limitaciones conocidas

- **Ventanas de administrador**: Windows (UIPI) bloquea el control de programas que corren como administrador si el servidor no se ejecuta también como administrador.
- **UAC, pantalla de bloqueo y Ctrl+Alt+Supr** corren en el escritorio seguro, que no se puede capturar ni controlar desde una app de usuario. Para eso hace falta un servicio de Windows con privilegios de SYSTEM.
- **Alt+F4 y Alt+Tab** los procesa primero tu Windows local, así que actúan sobre el cliente y no sobre el remoto.
- El cursor remoto no se dibuja en la imagen; ves tu propio cursor encima.

## Descargar los ejecutables

Cada cambio en `main` se compila solo en GitHub Actions:

- **Última compilación**: pestaña *Actions* → la ejecución más reciente → *Artifacts* → `AccesoRemoto-Windows` (se guarda 30 días).
- **Versión permanente**: *Releases* → *Draft a new release* → crear un tag (por ejemplo `v1.0`) → *Publish*. A los ~2 minutos la versión tiene adjuntos `ServidorRemoto.exe` y `ClienteRemoto.exe`.

Windows Defender o SmartScreen pueden avisar al abrirlos porque no están firmados. Elegí *Más información → Ejecutar de todas formas*.

## Compilar a mano (opcional)

```bat
pip install pyinstaller
pyinstaller --onefile --name ServidorRemoto --hidden-import pynput.keyboard._win32 --hidden-import pynput.mouse._win32 servidor.py
pyinstaller --onefile --windowed --name ClienteRemoto cliente.py
```

El servidor se compila **con consola** a propósito: siempre queda visible que está corriendo.

## Protocolo

Mensajes `[largo 4 bytes][tipo 1 byte][payload]` dentro de TLS. Tipos: `HELLO`, `AUTH`, `AUTH_OK`, `AUTH_FAIL`, `FRAME` (JPEG), `INPUT`, `CONFIG`, `INFO`, `FILE_START`, `FILE_CHUNK` y `FILE_END` (ver `protocolo.py`).
