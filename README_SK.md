# Automatizované spracovanie a nahrávanie IoC do MISPu

*Všetka zásluha patrí tvorcovi tohto nástroja - [Kristian Kapec](https://github.com/Kristian-Kapec/BP-IoC-extractor)*

CLI aplikácia na extrakciu indikátorov kompromitácie (IoC) z verejných zdrojov a ich import do platformy MISP. Podporuje webové články, TXT, CSV a PDF súbory, validáciu, normalizáciu, deduplikáciu, allowlist/exceptions pravidlá, export do JSON a potvrdený import do MISP cez PyMISP.

## Funkcie

- extrakcia IoC z URL, TXT, CSV a PDF vstupov,
- podporované IoC typy: URL, IPv4 adresy, domény, e-mailové adresy, MD5, SHA1 a SHA256,
- podpora custom regex patternov načítaných z `ioc_custom_regex.txt`,
- refang defangovaných hodnôt, napríklad `hxxp://`, `hxxps[://]`, `[.]`, `[@]`,
- validácia, normalizácia a deduplikácia hodnôt,
- allowlist a exceptions pravidlá pre jemné doladenie výsledkov,
- pokus o preferovanie IoC sekcie článku pred celým textom,
- confidence scoring podľa zdroja extrakcie (`ioc_section` vs. `full_article` / `file`),
- preview výsledkov, validačný report a runtime metriky,
- export výsledkov do JSON,
- vytvorenie alebo update MISP eventu po potvrdení používateľom,
- mapovanie IoC do MISP atribútov a objektov,
- pomocné evaluačné skripty pre fixtures a batch testovanie.

## Inštalácia

Vyžadovaná je funkčná inštalácia Pythonu 3.10 alebo novšieho.

```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install -r requirements.txt
```

## Konfigurácia MISPu

V koreňovom adresári projektu vytvor súbor `.env`:

```env
MISP_URL="https://misp.example.local"
MISP_KEY="your_api_key"
MISP_VERIFY_SSL="false"
MISP_TIMEOUT="15"
```

Poznámka: súbor `.env` obsahuje API kľúč a nemal by byť nahratý do repozitára, vyhnite sa tomu pridaním súboru `.env` do *.gitignore*.

Runtime nastavenia aplikácie sa dajú meniť aj cez súbor `config/app_config.json`:

```json
{
  "misp": {
    "distribution": 0,
    "sharing_group_id": 0,
    "analysis": 0,
    "publish_event": false,
    "allow_xdr_export": false,
    "enrich_event": false,
    "dissect_urls": false
  },

  "report": {
    "print_confidence": false,
    "print_validation_report": false,
    "print_attribute_preview": false,
    "print_metrics": false,
    "print_quick_preview": false
  }
}
```

Význam:

- `distribution` určuje MISP distribution level pre vytvorený alebo upravený event,
- `analysis` určuje analysis level eventu,
- `publish_event` určuje, či sa má po create/update zavolať publish.

## Použitie

Zobrazenie nápovedy:

```powershell
python app.py --help
```

Extrakcia z URL bez importu do MISP:

```powershell
python app.py --url https://example.com/threat-report
```

Extrakcia z TXT súboru:

```powershell
python app.py --file .\samples\iocs.txt
```

Extrakcia z CSV súboru:

```powershell
python app.py --file .\samples\iocs.csv
```

Extrakcia z PDF súboru:

```powershell
python app.py --file .\samples\report.pdf
```

Uloženie výsledku do JSON:

```powershell
python app.py --url https://example.com/threat-report --save-json outputs\result.json
```

Import do MISP po potvrdení:

```powershell
python app.py --file .\samples\report.pdf --push
```

Pri použití prepínača `--push` aplikácia najprv zobrazí náhľad extrahovaných dát a vypýta si potvrdenie. Ak nájde existujúci event s rovnakým zdrojom, zobrazí rozdiely a spýta sa, či sa má existujúci event aktualizovať.

## TXT, CSV a PDF vstupy

TXT súbor sa načíta ako plain text bez ďalšieho parsovania. Je vhodný napríklad pre threat intel feedy a zoznamy IoC po jednom na riadok.

CSV súbor sa číta ako text zo všetkých buniek. Vďaka tomu fungujú aj jednoduché súbory vo formáte:

```csv
type,value
url,hxxp://bad[.]example/payload
sha256,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

PDF súbory sa čítajú pomocou knižnice `pypdf`. Ak PDF obsahuje iba naskenované obrázky bez textovej vrstvy, aplikácia nebude mať z čoho extrahovať text. V takom prípade je potrebné najprv použiť OCR mimo tejto aplikácie.

## Allowlist a Exceptions

Projekt používa dva konfigurovateľné textové súbory v priečinku `config/`:

- `config/ioc_allowlist.txt` slúži ako force include. Hodnota zostane vo výsledku aj vtedy, keď by ju predvolený filter zablokoval.
- `config/ioc_exceptions.txt` slúži ako force exclude. Hodnota sa zahodí aj vtedy, keď by normálne prešla validáciou.

Formát riadku:

```txt
domain:packages.npm.org
email-src:user@proton.me
url:hxxp://bad[.]example/path
ip-dst:203.0.113.10
md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Prázdne riadky a riadky začínajúce znakom `#` sa ignorujú. Hodnoty sa pri načítaní normalizujú, takže defangované URL alebo domény sa porovnávajú s normalizovaným tvarom.

## Vlastné regulárne výrazy

Projekt automaticky načíta vlastné regexy z textového súboru `config/ioc_custom_regex.txt`.

Formát riadku:

```txt
btc-wallet:\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{20,60}\b
mutex:Global\\[A-Za-z0-9_-]+
npm-package:(?:^|[\s"'=:/])packages\.npm\.org\/((?:@[^\/\s"'<>]+\/)?[^\/\s"'<>?#]+)
```

Pravidlá:

- ľavá strana je názov regexu a vo výstupe sa objaví ako typ `custom:<name>`,
- názov môže obsahovať malé písmená, čísla, `-` a `_`,
- pravá strana je Python regex,
- prázdne riadky a riadky začínajúce `#` sa ignorujú.

Zhody cez vlastný regulárny výraz:

- zobrazia sa v preview a v JSON exporte,
- prejdú deduplikáciou rovnako ako ostatné typy,
- pri MISP mapovaní sa ukladajú ako atribúty typu `text` s tagom `ioc-type:custom:<name>`.

Ak regex obsahuje capture group, do výsledku sa uloží prvá neprázdna group. Ak group neobsahuje, uloží sa celá zhoda.

## Extrakcia IoC sekcie

Pri URL vstupoch sa aplikácia najprv pokúsi nájsť samostatnú IoC sekciu článku, napríklad podľa nadpisov typu:

- `Indicators of Compromise`
- `Indicator of Compromise`
- `IoCs`
- `IoC`

Ak sa IoC sekcia nájde a vyzerá použiteľne, extrakcia beží nad ňou. Inak sa použije celý článok.

Prideľovanie "Confidence" skóre je naviazané na `extraction_scope`:

- `ioc_section` -> validné IoC dostanú `high`,
- `full_article` a `file` -> systém prideľovania skóre je konzervatívnejší.

## Správanie pri importe do MISP

Nová udalosť obsahuje:

- atribút zdroja:
  - `link`, ak je zdroj webová URL,
  - `text`, ak je zdroj lokálny súbor,
- názov zdroja ako atribút typu `text`,
- neobjektové IoC ako atribúty,
- objektové IoC ako MISP objekty:
  - `url`,
  - `domain-ip`,
  - `file`,
- *~~tagy pre zdroj, validáciu, typ IoC a confidence~~*.

Pri duplicitnom zdroji aplikácia:

1. nájde existujúci event,
2. načíta jeho atribúty a objekty,
3. vypíše nové a už existujúce položky,
4. po potvrdení doplní iba nové hodnoty.

Poznámka: aplikácia udalosť vytvorí alebo aktualizuje, ale aktuálne nevolá finálne `publish`.

## Evaluačné skripty

Projekt obsahuje aj pomocné skripty pre overenie riešenia:

Spustenie evaluácie nad datasetom:

```powershell
python tools\build_fixture_report.py
```

Výstupy:

- `outputs/evaluation/fixture_report.json`
- `outputs/evaluation/fixture_report.md`

Spustenie batch evaluácie nad zoznamom URL / súborov:

```powershell
python tools\run_batch_manifest.py tools\sample_manifest.json
```

Výstupy:

- `outputs/evaluation/batch_report.json`
- `outputs/evaluation/batch_report.md`

## Štruktúra projektu

```txt
app.py                      hlavný CLI vstup
src/article_fetcher.py      načítanie a čistenie webových článkov
src/file_loader.py          načítanie TXT, CSV a PDF súborov
src/ioc_extractor.py        regex extrakcia IoC
src/ioc_processor.py        validácia, normalizácia, deduplikácia, allowlist a exceptions
src/misp_mapper.py          mapovanie IoC na MISP atribúty
src/misp_exporter.py        vytváranie a aktualizácia MISP eventov cez PyMISP
src/json_exporter.py        export do JSON
src/metrics.py              metriky a vyhodnotenie
tests/                      unit testy a testovacie dáta
tools/                      pomocné evaluačné skripty
```

## Testovanie

Spustenie testov:

```powershell
python -m unittest discover -s tests
```

Kontrola kompilácie:

```powershell
python -m compileall app.py src tests
```

## Známe obmedzenia

- Extrakcia z URL funguje spoľahlivo len na niektorých stránkach. Závisí od HTML štruktúry, dostupnosti obsahu v statickom HTML a od toho, či je text článku načítateľný bez browser renderingu.
- Nie všetky weby vracajú pri obyčajnom HTTP requeste plné telo článku. Niektoré stránky preto nemusia poskytnúť žiadne IoC aj napriek tomu, že ich v prehliadači obsahujú.
- PDF bez textovej vrstvy vyžaduje OCR mimo aplikácie.
- CSV parser je generický a číta všetky bunky ako text.
- README ani aplikácia momentálne neimplementujú OpenCTI workflow.
- Aplikácia aktuálne nevolá `publish`; event iba pripraví alebo uloží do MISP po kontrole používateľom.
