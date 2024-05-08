
#Rysunek 9. Przykład użycia komendy Read-Host do określenia zmiennej $folder. 

function wybor_folder {
    Write-Host -ForegroundColor Cyan 'Wskaz folder instalatora'
    Write-Host -ForegroundColor Cyan "Aktualnie jesteś w: $PSScriptRoot" 
    $Script:folder = Read-Host
}


#Rysunek 17. Funkcja globalna odpowiadająca za wyświetlanie błędów

function global:WyswietlenieBledu
{
    write-host "Wystąpił nieoczekiwany błąd" -foregroundColor Green 
    write-host "Treść błędu: $PSItem" - foregroundColor red
    pause
}



#Rysunek 18. Obsługa błędu try & catch wykorzystana w interfejsie.

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




#Rysunek 22. Kod źródłowy funkcji usuwania aktualizacji
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





#Rysunek 23. Kod źródłowy funkcji globalnej – połączenie

function global: polaczenie
{
$global:nazwakomputera = read-host 'Podaj nazwe urzadzenia' 
$global: Connection = Test-Connection $nazwakomputera -Count 1 -Quiet
}




#Rysunek 26. Funkcja kopiowania i instalacji w skrypcie Instalacji Oprogramowania
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






#Rysunek 35. Funkcja usuwania uszkodzonego wpisu w rejestrze.
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




#Rysunek 36. Kod źródłowy funkcji zmiany nazwy uszkodzonego folderu
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





#Rysunek 40 Ta funkcja restartuje ustawienia TPM na podanym komputerze.
function Restart-TPM {

    # Pobierz nazwę komputera
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $NazwaKomputera
    )

    # Pobierz stan szyfrowania
    $StanSzyfrowania = Invoke-Command -ComputerName $NazwaKomputera -ScriptBlock {
        & cmd.exe /c "manage-bde.exe -status"
    }

    # Wyłącz ochronę TPM
    if ($StanSzyfrowania.Contains('BitLocker jest włączony')) {
        Invoke-Command -ComputerName $NazwaKomputera -ScriptBlock {
            & cmd.exe /c "manage-bde.exe -protectors -disable C:"
        }
    }

    # Uruchom ponownie komputer
    Restart-Computer -ComputerName $NazwaKomputera

    # Odczekaj 1 sekundę
    Start-Sleep -Seconds 1

    # Włącz ochronę TPM
    if ($StanSzyfrowania.Contains('BitLocker jest włączony')) {
        Invoke-Command -ComputerName $NazwaKomputera -ScriptBlock {
            & cmd.exe /c "manage-bde.exe -protectors -enable C:"
        }
    }

    # Wyświetl komunikat o powodzeniu
    Write-Host "Wykonano restart ustawień TPM dla $NazwaKomputera"

}

# Wywołaj funkcję dla przykładowego komputera
Restart-TPM -NazwaKomputera "NazwaKomputera"











#Rysunek 48. Funkcja wysyłania wiadomości e-mail
# Ta funkcja wysyła wiadomość e-mail z informacją o komputerze, który nie odpowiada w sieci.

function WyslijPowiadomienie {

    # Pobierz parametry
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $NazwaKomputera,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Uzytkownik,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Skog,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Sprzełożony
    )

    # Ustaw parametry serwera SMTP
    $SEmailServer = "setphub.eur.mail.com"

    # Pobierz nazwę użytkownika
    $Sfrom = (Get-Netuser $Uzytkownik -DomainName "Nazwaboneny" | Select-Object -Property "SamAccountName").SamAccountName

    # Utwórz wiadomość e-mail
    $Semail = $Sfrom -replace "sazważytkownika", $Uzytkownik

    $Semail2 = "Automatyczne powiadomienie z $NazwaKomputera"
    $Semail3 = $Semail2 + "@firma.com"

    # Ustaw styl wiadomości
    $Styl = "margin: 10px; font-family: Calibri; font-size: 12pt; color: black; padding-left: 10px;"

    # Ustaw temat wiadomości
    $Temat = "Urządzenie $NazwaKomputera nie odpowiada w sieci"

    # Utwórz treść wiadomości
    $Tresc = @"
<p style="$Styl"><strong>Otrzymalismy informacje, że urządzenie $NazwaKomputera nie odpowiada w sieci od dłuższego czasu.</strong></p>
<p style="$Styl">&nbsp;</p>
<p style="$Styl">W związku z powyższym, prosimy o sprawdzenie urządzenia i podjęcie odpowiednich kroków w celu rozwiązania problemu.</p>
"@

    # Ustaw parametry wysyłania wiadomości
    $MailParams = @{
        From = $Semail
        To = $Skog
        Subject = $Temat
        Body = $Tresc
        SmtpServer = $SEmailServer
        BodyEncoding = [System.Text.UTF8Encoding]::UTF8
        Credential = (Get-Credential "lal")
    }

    # Wyślij wiadomość e-mail
    Send-MailMessage @MailParams -encoding UTF8 -Bcc $Semail3 -Cc "do.kogo.co@firma.com, $Sprzełożony"

    # Wyświetl komunikat o powodzeniu
    Write-Host "E-mail został wysłany"

}

# Wywołaj funkcję dla przykładowego komputera
WyslijPowiadomienie -NazwaKomputera "NazwaKomputera" -Uzytkownik "Jan.Kowalski" -Skog "jan.kowalski@firms.com" -Sprzełożony "jan.kowalski@firma.com"















