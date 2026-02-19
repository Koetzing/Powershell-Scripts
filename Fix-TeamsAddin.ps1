<#
.SYNOPSIS
    Post-Install Fix für das Microsoft Teams Meeting Add-in (TMA).
    Lädt den Bootstrapper bei Bedarf herunter und erzwingt die Registrierung.
#>

$WorkDir = "C:\Temp\TeamsAddinFix"
$BootstrapperPath = "C:\Temp\TeamsInstall\teamsbootstrapper.exe" # Pfad aus dem Hauptskript
$DownloadUrl = "https://go.microsoft.com/fwlink/?linkid=2243204"

# 1. Arbeitsverzeichnis vorbereiten
if (!(Test-Path $WorkDir)) { New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null }
Set-Location $WorkDir

Write-Host "--- Teams Meeting Add-in (TMA) Recovery ---" -ForegroundColor Cyan

# 2. Bootstrapper finden oder herunterladen
if (!(Test-Path $BootstrapperPath)) {
    $BootstrapperPath = Join-Path $WorkDir "teamsbootstrapper.exe"
    if (!(Test-Path $BootstrapperPath)) {
        Write-Host "[ INFO ] Bootstrapper nicht gefunden. Lade herunter..." -ForegroundColor Gray
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $BootstrapperPath
        Unblock-File $BootstrapperPath
    }
} else {
    Write-Host "[  OK  ] Bootstrapper unter $BootstrapperPath gefunden." -ForegroundColor Green
}

# 3. Add-in Installation erzwingen
Write-Host "[ STEP ] Registrierung des Add-ins wird gestartet..." -ForegroundColor Cyan

# Wir nutzen --installTMA (für moderne OS) und -p (als Fallback)
$Process = Start-Process -FilePath $BootstrapperPath -ArgumentList "--installTMA" -Wait -PassThru -NoNewWindow

if ($Process.ExitCode -ne 0) {
    Write-Host "[ WARN ] Standard-Installation fehlgeschlagen (Code $($Process.ExitCode))." -ForegroundColor Yellow
    Write-Host "[ INFO ] Versuche alternative Registrierung via Provisioning-Flag..." -ForegroundColor Gray
    
    # Alternativer Versuch (hilfreich, wenn MSIX Pfad unbekannt, erzwingt System-Check)
    & $BootstrapperPath -p
} else {
    Write-Host "[  OK  ] Registrierungsbefehl erfolgreich abgesetzt." -ForegroundColor Green
}

# 4. Verifizierung (Registry Check)
$RegPath = "HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect"
if (Test-Path $RegPath) {
    Write-Host "[  OK  ] Registry-Eintrag für Outlook Add-in wurde gefunden." -ForegroundColor Green
} else {
    Write-Host "[ HINWEIS ] Add-in Registry-Key noch nicht sichtbar." -ForegroundColor Yellow
    Write-Host "           Tipp: Teams muss einmalig gestartet werden, um die" -ForegroundColor Gray
    Write-Host "           Benutzer-Registrierung abzuschließen." -ForegroundColor Gray
}

Write-Host "`nFertig. Bitte starten Sie Outlook neu, um das Add-in zu prüfen." -ForegroundColor Cyan
