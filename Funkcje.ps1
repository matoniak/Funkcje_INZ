

#Rysunek 10. Funkcja globalna odpowiadająca za wyświetlanie błędów

function global:WyswietlenieBledu
{
    write-host "Wystąpił nieoczekiwany błąd" -foregroundColor Green 
    write-host "Treść błędu: $PSItem" - foregroundColor red
    pause
}
function pokaz_Menu
{

do
{

    pokaz_menu -tytul 'MENU'
	try
    {
    catch [System.Management.Automation.RuntimeException]
    {
    Write-Host "Wybór nie jest liczbą. Proszę spróbować ponownie." -foregroundColor red
	pause
	}
	catch
	{
	WyswietlenieBledu
	}

}until($wybor -eq '99')
}


#Rysunek 11. Obsługa błędu try & catch wykorzystana w interfejsie.

function global:WyswietlenieBledu
{
    write-host "Wystąpił nieoczekiwany błąd" -foregroundColor Green 
    write-host "Treść błędu: $PSItem" - foregroundColor red
    pause
}
function pokaz_Menu
{

do
{

    pokaz_menu -tytul 'MENU'
	try
    {
    catch [System.Management.Automation.RuntimeException]
    {
    Write-Host "Wybór nie jest liczbą. Proszę spróbować ponownie." -foregroundColor red
	pause
	}
	catch
	{
	WyswietlenieBledu
	}

}until($wybor -eq '99')
}



#Rysunek 16. Kod źródłowy funkcji usuwania aplikacji

function usuwanie_aplikacji {
    $nazwakomputera = Read-Host "Podaj nazwę komputera"

    try {
        $registryPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        $key = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $nazwakomputera)
        $subkeys = $key.OpenSubKey($registryPath).GetSubKeyNames()

        if ($subkeys) {
            Write-Host -ForegroundColor Cyan -BackgroundColor Black "`nLista aplikacji na komputerze $($nazwakomputera):"
            $applications = @()
            foreach ($subkey in $subkeys) {
                $programName = $key.OpenSubKey("$registryPath\$subkey").GetValue("DisplayName")
                if ($programName -ne $null) {
                    $applications += $programName
                    Write-Host -ForegroundColor Cyan -BackgroundColor Black $programName
                }
            }
            $cochcesz = Read-Host "Podaj część nazwy aplikacji do usunięcia"
            $foundApplications = $applications | Where-Object { $_ -like "*$cochcesz*" }
            if ($foundApplications.Count -gt 0) {
                Write-Host "Znalezione aplikacje:"
                $foundApplications | ForEach-Object { Write-Host $_ }
                $toRemove = Read-Host "Wybierz aplikację do usunięcia z powyższej listy"
                $uninstallKey = $key.OpenSubKey($registryPath)            
                $subkeyName = $uninstallKey.GetSubKeyNames() | Where-Object { $uninstallKey.OpenSubKey($_).GetValue("DisplayName") -eq $toRemove }
                $uninstallString = $uninstallKey.OpenSubKey($subkeyName).GetValue("UninstallString")

                if ($uninstallString) {
                    Write-Host "Uninstall String: $uninstallString"
                    $result = Invoke-Command -ComputerName $nazwakomputera -ScriptBlock {
                        Start-Process -FilePath "$using:uninstallString" -ArgumentList "/quiet", "/norestart" -Wait
                        return $?
                    }
                    if ($result) {
                        Write-Host -ForegroundColor Cyan -BackgroundColor Black "`nAplikacja $toRemove została usunięta."
                    } else {
                        Write-Host -ForegroundColor Cyan -BackgroundColor Black "`nNie udało się usunąć aplikacji $toRemove."
                    }
                } else {
                    Write-Host -ForegroundColor Cyan -BackgroundColor Black "`nNie udało się odnaleźć lub usunąć aplikacji $toRemove."
                }
            } else {
                Write-Host -ForegroundColor Cyan -BackgroundColor Black "`nPodana część nazwy aplikacji nie znajduje się na liście."
            }
        } else {
            Write-Host -ForegroundColor Cyan -BackgroundColor Black "`nNie można uzyskać listy aplikacji na komputerze $($nazwakomputera)."
        }
    } catch {
        Write-Host -ForegroundColor Cyan -BackgroundColor Black "Wystąpił błąd podczas pobierania listy aplikacji."
        Write-Host -ForegroundColor Cyan -BackgroundColor Black "Błąd: $_"
    }
}

usuwanie_aplikacji




#Rysunek 18. Kod źródłowy funkcji usuwania aktualizacji
function usuwanie_aktualizacji {
    param (
        [string]$nazwakomputera
    )

    $listaaktualizacji = Get-Hotfix -cn $nazwakomputera | Select HotfixID, Description, InstalledOn | Sort-Object HotfixID | Format-Table -AutoSize | Out-String
    Write-Host -ForegroundColor Cyan -BackgroundColor Black "`nlista aktualizacji: "
    Write-Host -ForegroundColor Cyan $listaaktualizacji
    Write-Host -ForegroundColor Cyan -BackgroundColor Black "Prosze o podanie aktualizacji z listy: "
    $jaka_aktualizacja = Read-Host

    $jaka_aktualizacja2 = $jaka_aktualizacja.Replace("KB","")
    Write-Host -ForegroundColor Cyan -BackgroundColor Black "`nUsuwanie $jaka_aktualizacja w toku..."

    $odinstaluj = "cmd.exe /c wusa.exe /uninstall /KB:$jaka_aktualizacja2 /quiet /norestart" 
    Invoke-Command -ComputerName $nazwakomputera -ArgumentList $odinstaluj -ScriptBlock { 
        param($odinstaluj)
        Invoke-Expression $odinstaluj
    }

    while (@(Get-Process wusa -ComputerName $nazwakomputera -ErrorAction SilentlyContinue).Count -ne 0) {
        Start-Sleep 3
        Write-Host -ForegroundColor Cyan -BackgroundColor Black "Usuwanie $jaka_aktualizacja2 w toku..."
        Write-Host -ForegroundColor Cyan -BackgroundColor Black "`nAktualizacja $jaka_aktualizacja została usunięta."
    }
    else {
    }

    Write-Host -ForegroundColor Cyan -BackgroundColor Black "Nie znaleziono aktualizacji $jaka_aktualizacja."
    pause
}





#Rysunek 20. Funkcja kopiowania i instalacji w skrypcie Instalacji Oprogramowania

function kopiowanie {
    # Ustawienie ścieżek
    $Script:sciezka = "\\NazwaKomputera\cs\temp\instalacja"
    $Script:sciezka2 = "$sciezka\Sinstalator_nazwa"

    # Sprawdzenie, czy folder istnieje
    if (-not (Test-Path $sciezka)) {
        # Komunikat o tworzeniu folderu
        Write-Host -ForegroundColor cyan -BackgroundColor black "Tworzenie folderu $sciezka"

        # Tworzenie folderu
        New-Item -ItemType Directory -Force -Path $sciezka
    }

    # Kopiowanie pliku instalatora
    Write-Host -ForegroundColor cyan -BackgroundColor black "Kopiowanie na $NazwaKomputera trwa..."
    Copy-Item "Ścieżka_do_pliku_instalatora" -Destination $sciezka -Recurse

    # Komunikat o zakończeniu kopiowania
    Write-Host -ForegroundColor cyan -BackgroundColor black "Skopiowano plik Sinstalator_nazwa"

    # Wyświetlenie listy plików w folderze
    Get-ChildItem $sciezka
}

function instalacja {
    param (
        [string]$NazwaKomputera,
        [string]$sciezka2
    )

    # Utworzenie nazwy logu
    $log = "instalacja_$(((Get-Date).ToUniversalTime()).ToString("yyyyMMddhhmmss")).log"

    # Komunikat o instalacji
    Write-Host -ForegroundColor cyan -BackgroundColor black "Trwa instalacja Sinstalator_nazwa na $NazwaKomputera..."

    # Odczekanie 5 sekund
    Start-Sleep -Seconds 5

    # Wywołanie skryptu na komputerze zdalnym
    Invoke-Command -ComputerName $NazwaKomputera -ScriptBlock {
        param($sciezka2, $log)

        # Uruchamianie instalatora
        Msiexec /i $sciezka2 /log $log

        # Odczekanie 1 sekundy
        Start-Sleep -Seconds 1

        # Komunikat o zakończeniu instalacji
        Write-Host -ForegroundColor cyan -BackgroundColor black "Zainstalowano Sinstalator_nazwa na $using:NazwaKomputera"

        # Wyświetlenie pustej linii
        Write-Host

        # Komunikat o logu z instalacji
        Write-Host "Log z instalacji:"

        # Pobranie zawartości logu
        $zawartoscLog = Get-Content $log

        # Wyświetlenie zawartości logu
        Write-Output $zawartoscLog
    } -ArgumentList $sciezka2, $log
}

# Wywołanie funkcji kopiowania
kopiowanie

# Wywołanie funkcji instalacji
instalacja -NazwaKomputera "NazwaKomputera"


#Rysunek 19. Kod źródłowy funkcji globalnej – połączenie

function global: polaczenie
{
$global:nazwakomputera = read-host 'Podaj nazwe urzadzenia' 
$global: Connection = Test-Connection $nazwakomputera -Count 1 -Quiet
}


#Rysunek 20. Funkcja kopiowania i instalacji w skrypcie Instalacji Oprogramowania
function kopiowanie {
    # Ustawienie ścieżek
    $Script:sciezka = "\\NazwaKomputera\cs\temp\instalacja"
    $Script:sciezka2 = "$sciezka\Sinstalator_nazwa"

    # Sprawdzenie, czy folder istnieje
    if (-not (Test-Path $sciezka)) {
        # Komunikat o tworzeniu folderu
        Write-Host -ForegroundColor cyan -BackgroundColor black "Tworzenie folderu $sciezka"

        # Tworzenie folderu
        New-Item -ItemType Directory -Force -Path $sciezka
    }

    # Kopiowanie pliku instalatora
    Write-Host -ForegroundColor cyan -BackgroundColor black "Kopiowanie na $NazwaKomputera trwa..."
    Copy-Item "Ścieżka_do_pliku_instalatora" -Destination $sciezka -Recurse

    # Komunikat o zakończeniu kopiowania
    Write-Host -ForegroundColor cyan -BackgroundColor black "Skopiowano plik Sinstalator_nazwa"

    # Wyświetlenie listy plików w folderze
    Get-ChildItem $sciezka
}

function instalacja {
    param (
        [string]$NazwaKomputera,
        [string]$sciezka2
    )

    # Utworzenie nazwy logu
    $log = "instalacja_$(((Get-Date).ToUniversalTime()).ToString("yyyyMMddhhmmss")).log"

    # Komunikat o instalacji
    Write-Host -ForegroundColor cyan -BackgroundColor black "Trwa instalacja Sinstalator_nazwa na $NazwaKomputera..."

    # Odczekanie 5 sekund
    Start-Sleep -Seconds 5

    # Wywołanie skryptu na komputerze zdalnym
    Invoke-Command -ComputerName $NazwaKomputera -ScriptBlock {
        param($sciezka2, $log)

        # Uruchamianie instalatora
        Msiexec /i $sciezka2 /log $log

        # Odczekanie 1 sekundy
        Start-Sleep -Seconds 1

        # Komunikat o zakończeniu instalacji
        Write-Host -ForegroundColor cyan -BackgroundColor black "Zainstalowano Sinstalator_nazwa na $using:NazwaKomputera"

        # Wyświetlenie pustej linii
        Write-Host

        # Komunikat o logu z instalacji
        Write-Host "Log z instalacji:"

        # Pobranie zawartości logu
        $zawartoscLog = Get-Content $log

        # Wyświetlenie zawartości logu
        Write-Output $zawartoscLog
    } -ArgumentList $sciezka2, $log
}

# Wywołanie funkcji kopiowania
kopiowanie

# Wywołanie funkcji instalacji
instalacja -NazwaKomputera "NazwaKomputera"


#Rysunek 31. Funkcja usuwania uszkodzonego wpisu w rejestrze.
Function CzyszczenieFelu($nazwaKomputera) {
    # Pobierz SID użytkownika
    $strSID = (Get-WmiObject Win32_UserProfile | Where-Object { $_.LocalPath.Split("\")[-1] -eq $env:USERNAME }).SID

    # Sprawdź, czy SID zostało pobrane poprawnie
    If ($strSID) {
        # Utwórz zmienną z pełną ścieżką do klucza rejestru
        $strRegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$($strSID)"

        # Sprawdź, czy klucz rejestru istnieje
        If (Test-Path $strRegistryPath) {
            # Usuń klucz rejestru
            Remove-Item -Path $strRegistryPath -Force -Confirm:$false

            # Wyświetl komunikat o powodzeniu
            Write-Host "Upiw w rejestrze dla profilu $($env:USERNAME) na komputerze $nazwaKomputera usunięto pomyślnie"
        } Else {
            # Wyświetl komunikat o błędzie
            Write-Warning "Klucz rejestru dla profilu $($env:USERNAME) na komputerze $nazwaKomputera nie istnieje."
        }
    } Else {
        # Wyświetl komunikat o błędzie
        Write-Warning "Nie udało się pobrać SID dla użytkownika $($env:USERNAME)."
    }
}

# Wywołaj funkcję
CzyszczenieFelu "WIN-99DU8TMFIPN"




#Rysunek 32. Kod źródłowy funkcji zmiany nazwy uszkodzonego folderu
if ($Connection -eq "True") {
    function czyszczenie {
        Wait-Host
        Write-Host -BackgroundColor black -ForegroundColor cyan "Loginy wpisane w rejestrze:"
        $Shasz = Invoke-Command -ComputerName $NazwaKomputera -ScriptBlock {
            Get-ChildItem 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' -Recurse -ErrorAction Stop | Get-ItemProperty Name, ProfileImagePath -ErrorAction SilentlyContinue
        }
        $Shasz | Select-Object ProfileImagePath, PSPath | Out-String

        Write-Host $Shasz

        czyszczenie

        Write-Host -BackgroundColor black -ForegroundColor cyan "DOSTĘPNE FOLDERY W LOKALIZACJI C:\Users"
        $SdostepneFoldery = Get-ChildItem -Directory "\\$NazwaKomputera\c$\users\" | Out-String
        Write-Host $SdostepneFoldery

        $Login = Read-Host "Ktory login wybierasz"

        $SciezkaLogin = "C:\users\$Login"
        $Shaszowany = "C:\Users\$Login\$((Get-Date).ToString("dd-MM-yyyy-hh-mm"))"

        if (Test-Path "\\$NazwaKomputera\c$\users\$Login") {
            Invoke-Command -ComputerName $NazwaKomputera -ArgumentList $SciezkaLogin, $Shaszowany -ScriptBlock {
                Rename-Item -Path $args[0] -NewName $args[1]
                Start-Sleep -Seconds 3
            }

            Clear-Variable SdostepneFoldery
            Write-Host "Foldery w C:\Users po wykonaniu skryptu:"
            $SdostepneFoldery2 = Get-ChildItem -Directory "\\$NazwaKomputera\c$\users\" | Out-String
            Write-Host $SdostepneFoldery2
        } else {
            Write-Host -ForegroundColor Red "Folder $SciezkaLogin nie istnieje"
            Pause
        }
    }

    czyszczenie
} else {
    # Brak połączenia z komputerem zdalnym
}



#Rysunek 36. Wykorzystanie polecenia manage-bde.exe

# Zmień te wartości zgodnie z Twoim środowiskiem
$NazwaKomputera = "NazwaKomputera"
$HasloAdministratora = "HasloAdministratora"

# Sprawdzenie dostępności komputera
if (Test-Connection -ComputerName $NazwaKomputera -ErrorAction Stop) {
    Write-Host "Komputer $NazwaKomputera jest dostępny."
} else {
    Write-Host "Komputer $NazwaKomputera jest niedostępny."
    Exit
}

# Wyłączenie ochrony TPM
$WynikWyłączenia = Invoke-Command -ComputerName $NazwaKomputera -ScriptBlock {
    try {
        Clear-Tpm -Force
        $Wynik = "Wyłączono ochronę TPM."
    } catch {
        $Wynik = $_.Exception.Message
    }
    $Wynik
}

if ($WynikWyłączenia -match "Wyłączono ochronę TPM.") {
    Write-Host "Ochrona TPM została wyłączona na komputerze $NazwaKomputera."
} else {
    Write-Host "Wystąpił błąd podczas wyłączania ochrony TPM na komputerze $NazwaKomputera:"
    Write-Host $WynikWyłączenia
    Exit
}

# Restart komputera
Invoke-Command -ComputerName $NazwaKomputera -ScriptBlock {
    Restart-Computer
}

# Włączenie ochrony TPM
Start-Sleep -Seconds 60

$WynikWłączenia = Invoke-Command -ComputerName $NazwaKomputera -ScriptBlock {
    try {
        Enable-Tpm -Force
        $Wynik = "Włączono ochronę TPM."
    } catch {
        $Wynik = $_.Exception.Message
    }
    $Wynik
}

if ($WynikWłączenia -match "Włączono ochronę TPM.") {
    Write-Host "Ochrona TPM została włączona na komputerze $NazwaKomputera."
} else {
    Write-Host "Wystąpił błąd podczas włączania ochrony TPM na komputerze $NazwaKomputera:"
    Write-Host $WynikWłączenia
}

# Komunikat końcowy
Write-Host "Wykonano restart ustawień TPM dla $NazwaKomputera."


