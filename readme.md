# Správce hesel
## Zadání
### Správce hesel s dvoufaktorovou autentizací
Naprogramujte aplikaci k úschově hesel s dvoufaktorovou autentizací uživatele. Aplikace bude 
provádět šifrování souborů s hesly na základě uživatelem zvoleného algoritmu a délky klíče.
Dále bude také zajištěna kontrola integrity souboru s hesly. Pro šifrování souboru a jeho
kontrolu integrity implementujte minimálně tři různé algoritmy. Aplikace bude zaznamenávat
proběhlé události (přístup do aplikace, k jednotlivým heslům, …) do logu včetně času.

## Řešení
Tento repozitář obsahuje zdrojové kódy pro projekt do předmětu Aplikovaná kryptografie. Aplikace funguje jako lokálně
uložený správce hesel s dvoufaktorovou autentizací pomocí Google Authenticator.<br>
Podrobný popis funkce spolu s vývojovým diagramem obsahuje dokument "Správce hesel - dokumentace".

## Spuštění
Aplikace se spouští v "password_manager.py" bez dalších vstupních parametrů.
```Bash
py ./src/password_manager.py
```
Pro nainstalování knihoven lze použít příkaz:
```Bash
pip install -r requirements.txt
```
Spuštění je dále možné pomocí přiloženého executable souboru.
