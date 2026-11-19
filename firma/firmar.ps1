<#
  Firma ejecutables con el certificado guardado en los secretos de GitHub.
  Lo usa el workflow; lee FIRMA_PFX_BASE64 y FIRMA_PFX_PASSWORD del entorno.
#>
param(
    [Parameter(Mandatory = $true)][string[]]$Archivos,
    [string]$Salida = "dist",
    [string]$Descripcion = "Acceso Remoto"
)
$ErrorActionPreference = "Stop"
if (-not $env:FIRMA_PFX_BASE64 -or -not $env:FIRMA_PFX_PASSWORD) {
    throw "Faltan FIRMA_PFX_BASE64 / FIRMA_PFX_PASSWORD"
}
$signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName | Select-Object -Last 1
if (-not $signtool) { throw "No se encontró signtool.exe (Windows SDK)" }

$pfx = Join-Path ([IO.Path]::GetTempPath()) ("firma_" + [guid]::NewGuid().ToString("N") + ".pfx")
[IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:FIRMA_PFX_BASE64))
try {
    $firmado = $false
    foreach ($ts in "http://timestamp.digicert.com", "http://timestamp.sectigo.com") {
        & $signtool.FullName sign /fd SHA256 /f $pfx /p $env:FIRMA_PFX_PASSWORD `
            /tr $ts /td SHA256 /d $Descripcion @Archivos
        if ($LASTEXITCODE -eq 0) { $firmado = $true; break }
        Write-Warning "Falló la firma con el sello de tiempo $ts, probando otro..."
    }
    if (-not $firmado) { throw "No se pudieron firmar los ejecutables" }

    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($pfx, $env:FIRMA_PFX_PASSWORD)
    $cer = Join-Path $Salida "AccesoRemoto-Firma.cer"
    [IO.File]::WriteAllBytes($cer, $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    Write-Host "Firmado por $($cert.Subject) - huella $($cert.Thumbprint) - vence $($cert.NotAfter.ToString('yyyy-MM-dd'))"
}
finally {
    Remove-Item $pfx -Force -ErrorAction SilentlyContinue
}
