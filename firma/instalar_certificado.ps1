<#
  Hace que esta PC confíe en los programas firmados con tu certificado.
  Ejecutar como administrador (instalar_certificado.bat lo pide solo).

    * Instala AccesoRemoto-Firma.cer como raíz de confianza y editor de confianza.
    * Desbloquea los .exe de esta carpeta (quita la marca "descargado de
      Internet", que es lo que dispara el aviso de SmartScreen).

  Para quitarlo:  powershell -ExecutionPolicy Bypass -File instalar_certificado.ps1 -Desinstalar
#>
param([switch]$Desinstalar)
$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$cer = Join-Path $dir "AccesoRemoto-Firma.cer"
if (-not (Test-Path $cer)) { throw "No se encontró AccesoRemoto-Firma.cer en $dir" }
$cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($cer)
$almacenes = "Cert:\LocalMachine\Root", "Cert:\LocalMachine\TrustedPublisher"

if ($Desinstalar) {
    foreach ($a in $almacenes) {
        Get-ChildItem $a | Where-Object Thumbprint -eq $cert.Thumbprint | Remove-Item
    }
    Write-Host "Certificado quitado de esta PC."
    return
}

foreach ($a in $almacenes) { Import-Certificate -FilePath $cer -CertStoreLocation $a | Out-Null }
Write-Host "Certificado instalado: $($cert.Subject)  (huella $($cert.Thumbprint))"
Write-Host ""
$malos = 0
Get-ChildItem $dir -Filter *.exe | ForEach-Object {
    Unblock-File $_.FullName
    $s = Get-AuthenticodeSignature $_.FullName
    if ($s.Status -ne "Valid") { $malos++ }
    Write-Host ("  {0,-22} firma: {1}" -f $_.Name, $s.Status)
}
if ($malos) { Write-Warning "Hay ejecutables sin firma válida."; exit 2 }
