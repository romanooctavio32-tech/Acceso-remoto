<#
  Crea el certificado propio de firma de código (se ejecuta UNA vez, en tu PC).

  Genera:
    firma_privada.pfx        clave privada + certificado  -> GUARDALO EN LUGAR SEGURO
    AccesoRemoto-Firma.cer   certificado público (el que se instala en las PCs)
    secretos_github.txt      los dos valores para cargar en GitHub

  Si tenés GitHub CLI (gh) iniciado, carga los secretos solo. Si no, abre la
  página de secretos del repositorio y el archivo con los valores para copiar.
#>
param(
    [string]$Nombre = "Octavio",
    [int]$Anios = 5,
    [string]$Repo = "romanooctavio32-tech/Acceso-remoto",
    [switch]$SinSubir
)
$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pfx = Join-Path $dir "firma_privada.pfx"
$cer = Join-Path $dir "AccesoRemoto-Firma.cer"
$txt = Join-Path $dir "secretos_github.txt"

if ((Test-Path $pfx) -and -not $SinSubir) {
    $r = Read-Host "Ya existe firma_privada.pfx. ¿Reemplazarlo? Las PCs con el certificado anterior van a tener que instalar el nuevo (s/N)"
    if ($r -notmatch '^[sS]') { Write-Host "Cancelado."; exit 1 }
}

Write-Host "Creando certificado de firma para '$Nombre' (válido $Anios años)..."
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$Nombre" `
    -FriendlyName "Firma de código - $Nombre" -KeyAlgorithm RSA -KeyLength 3072 `
    -HashAlgorithm SHA256 -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears($Anios) `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -TextExtension @("2.5.29.19={critical}{text}ca=0")   # no puede actuar como autoridad

$bytes = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$clave = [Convert]::ToBase64String($bytes)
$seg = ConvertTo-SecureString $clave -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $seg | Out-Null
Export-Certificate -Cert $cert -FilePath $cer | Out-Null
# La copia queda solo en el .pfx; se quita del almacén de Windows
Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey

$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($pfx))
@"
Cargá estos DOS secretos en: https://github.com/$Repo/settings/secrets/actions/new
(Nombre exacto a la izquierda del '=', valor todo lo que está a la derecha)

FIRMA_PFX_BASE64=$b64

FIRMA_PFX_PASSWORD=$clave

Después guardá firma_privada.pfx y esta contraseña en un lugar seguro y borrá este archivo.
"@ | Set-Content -Path $txt -Encoding UTF8

Write-Host ""
Write-Host "Certificado creado:"
Write-Host "  Titular : $($cert.Subject)"
Write-Host "  Huella  : $($cert.Thumbprint)"
Write-Host "  Vence   : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host ""

if ($SinSubir) { return }

$gh = Get-Command gh -ErrorAction SilentlyContinue
if ($gh) {
    & gh auth status *> $null
    if ($LASTEXITCODE -eq 0) {
        $b64   | & gh secret set FIRMA_PFX_BASE64   --repo $Repo
        $clave | & gh secret set FIRMA_PFX_PASSWORD --repo $Repo
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Secretos cargados en GitHub con gh. Listo."
            Write-Host "Guardá firma_privada.pfx y secretos_github.txt en un lugar seguro."
            return
        }
    }
}
Write-Host "Abriendo la página de secretos de GitHub y el archivo con los valores..."
Start-Process "https://github.com/$Repo/settings/secrets/actions/new"
Start-Process notepad.exe $txt
