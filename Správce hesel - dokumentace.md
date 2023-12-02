# Správce hesel
## 1. Funkce programu
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
py ./password_manager.py
```
V souborech je dále přiložen také .exe soubor ze kterého je aplikace spustitelná i bez příkazové řádky.
## 4. Seznam použitých knihoven
## 5. Vývojový diagram
![Vývojový diagram](/img/Flow_chart.png)