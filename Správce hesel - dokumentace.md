# Správce hesel
## 1. Funkce programu
### 1.1 Vlastnosti programu
Správce hesel umožnuje ukládat hesla v šifrované databázi s přístupem chráněným heslem a dvoufaktorovým ověřením pomocí
Google Authenticator mobilní aplikace a webového API. Při prvním spuštění si uživatel vytvoří účet s loginem a heslem.
Z těchtu údajů je následně vygenerován QR kód, který si uživatel naskenuje do aplikace Google Authenticator (dále jen 
GA), kde se přidá generátor 6ti ciferného čísla pro tuto aplikaci. Následně je uživatel vyzván k přihlášení a pokud jsou
přihlašovací údaje správné, tak je následně požadováno zadání bezpečnostního pinu z GA. Je-li autentizace tohoto pinu
úspěšná, je rozšifrována databáze a provedeno její načtení a uživateli je umožněn přístup k datům uloženým v této 
databázi. V tuto chvíli může uživatel provádět operace s uloženými hesly a nastavit parametry šifrování programu.
Pokud došlo ke změně těchto parametrů, je uživatel vyzván k zadání přístupového hesla. Databáze je následně zašifrována,
zašifrována jsou metadata a vše je následně uloženo do složky "pmfiles". Při opětovném otevření probíhá vše stejně,
jen se uživateli stačí pouze přihlásit.
### 1.2 Technické vlastnosti
První ověření hesla probíhá porovnáním otisků vytvořených pomocí SHA-256 z loginu a hesla. Pro šifrování databáze
si může uživatel vybrat ze 3 algoritmů: AES-GCM, Camellia-CBC a Fernet. Až na Fernet si uživatel může vybrat ze 3 délek
klíčů a to 128, 192 a 256 bitů. Fernet pracuje s fixní délkou 256 bitů, proto je tedy uživateli odepřena možnost tuto
hondotu v případě použití této šifry nastavit. Metadata s potřebnými informacemi jsou šifrována pomocí 4096 bitového
RSA, kde je soukormý klíč šifrován pomocí AES-CBC se 128 bitovým klíčem vyderivovaným ze statického hesla uloženého v
programu s bitovým posunem.
## 2. Struktura programu
Program se spouští ze souboru "password_manager.py" ve které se volá funkce spuštění a běhu GUI v souboru "ui.py".
Mezi tímto frontendem a samotným backendem stojí "runtime_functions.py", který se chová jako interface mezi těmito
dvěma celky. O hlavní správu a práci s databází se stará "blockchain_manager.py". Obsahuje funkce pro načtení a uložení
databáze, přídání, úpravu a odebrání jednotlivých záznamů hesel. Soubor "integrity_manager.py" šifruje databázi a
také se stará o šifrování a ukládání metadat. Také jsou zde metadata uložena a generují se zde klíče pro šifrovací
funkce. O druhý autentizační faktor se stará "authenticator.py". Zde probíhá generace QR kódu pro spárování s Google 
Authenticator a také ověření zadaného bezpenčostního pinu z aplikace. Logování zajišťuje "logger.py". Seznam cest k
souborům se nachází v "utils.py".
## 3. Spuštění programu
Entry point se nachází v "password_manager.py". Funkce nemá žádné vstupní parametry.
```Bash
py ./src/password_manager.py
```
V souborech je dále přiložen také .exe soubor ze kterého je aplikace spustitelná i bez příkazové řádky.
## 4. Seznam použitých knihoven
Seznam použitých knihoven je obsažen v souboru "requirements.txt". Pro nainstalování knihoven lze použít příkaz:
```Bash
pip install -r requirements.txt
```
## 5. Vývojový diagram
![Vývojový diagram](/img/Flow_chart.png)