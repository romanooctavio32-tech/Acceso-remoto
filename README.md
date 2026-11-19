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

## Firma con certificado propio

Los `.exe` se firman automáticamente si el repositorio tiene los secretos `FIRMA_PFX_BASE64` y `FIRMA_PFX_PASSWORD`. Si no están, se compilan sin firmar y el workflow muestra un aviso.

**Configuración (una sola vez, en tu PC con Windows):**

1. Descargá la carpeta `firma` (o el repositorio entero) y ejecutá `firma\crear_certificado.bat`.
   Para que figure otro nombre como titular: `crear_certificado.bat -Nombre "Mi Empresa"`.
2. Si tenés [GitHub CLI](https://cli.github.com) con la sesión iniciada, los secretos se cargan solos. Si no, se abren la página de secretos del repositorio y un Bloc de notas con los dos valores para copiar y pegar.
3. Guardá `firma_privada.pfx` y su contraseña en un lugar seguro, fuera del repositorio. Si los perdés, hay que crear otro certificado y volver a instalarlo en todas las PCs.

**En cada PC donde se usen los programas:**

Poné `ServidorRemoto.exe` / `ClienteRemoto.exe`, `AccesoRemoto-Firma.cer` e `instalar_certificado.bat` en la misma carpeta y ejecutá el `.bat` (pide permisos de administrador). Este script:

- instala el certificado como raíz y editor de confianza, así que la firma figura como válida y aparece tu nombre como editor;
- desbloquea los `.exe` de esa carpeta (les quita la marca de "descargado de Internet"), que es lo que hace saltar SmartScreen.

En la empresa se puede distribuir el `.cer` por GPO: *Configuración del equipo → Directivas → Configuración de Windows → Configuración de seguridad → Directivas de clave pública*, en los almacenes *Entidades de certificación raíz de confianza* y *Editores de confianza*.

Para quitarlo de una PC: `powershell -ExecutionPolicy Bypass -File instalar_certificado.ps1 -Desinstalar` (como administrador).

**Límites:** un certificado propio solo genera confianza en las PCs donde lo instalás. Para SmartScreen, en cualquier otra PC cuenta igual que no tener firma, así que ahí vas a seguir viendo *Más información → Ejecutar de todas formas*. Para distribuir los programas al público hace falta un certificado comercial.

## Compilar a mano (opcional)

```bat
pip install pyinstaller
pyinstaller --onefile --name ServidorRemoto --hidden-import pynput.keyboard._win32 --hidden-import pynput.mouse._win32 servidor.py
pyinstaller --onefile --windowed --name ClienteRemoto cliente.py
```

El servidor se compila **con consola** a propósito: siempre queda visible que está corriendo.

## Protocolo

Mensajes `[largo 4 bytes][tipo 1 byte][payload]` dentro de TLS. Tipos: `HELLO`, `AUTH`, `AUTH_OK`, `AUTH_FAIL`, `FRAME` (JPEG), `INPUT`, `CONFIG`, `INFO`, `FILE_START`, `FILE_CHUNK` y `FILE_END` (ver `protocolo.py`).
