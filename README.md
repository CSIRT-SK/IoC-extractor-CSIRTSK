# IoC Processor and Extractor to MISP

*All credit goes to the creator of this tool - [Kristian Kapec](https://github.com/Kristian-Kapec/BP-IoC-extractor)*

CLI application for extracting Indicators of Compromise (IoCs) from public sources and importing them into the MISP platform. Supports web articles, TXT, CSV, and PDF files, validation, normalization, deduplication, allowlist/exceptions rules, JSON export, and confirmed import into MISP through PyMISP.

## Features

* extraction of IoCs from URL, TXT, CSV, and PDF inputs,
* supported IoC types: URL, IPv4 addresses, domains, email addresses, MD5, SHA1, and SHA256,
* support for custom regex patterns loaded from `ioc_custom_regex.txt`,
* refang of defanged values, for example `hxxp://`, `hxxps[://]`, `[.]`, `[@]`,
* validation, normalization, and deduplication of values,
* allowlist and exceptions rules for fine-tuning results,
* attempt to prioritize the IoC section of an article over the full text,
* confidence scoring based on extraction source (`ioc_section` vs. `full_article` / `file`),
* results preview, validation report, and runtime metrics,
* export of results to JSON,
* creation or update of a MISP event after user confirmation,
* mapping IoCs to MISP attributes and objects,
* helper evaluation scripts for fixtures and batch testing.

## Installation

A working installation of Python 3.10 or newer is required.

```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install -r requirements.txt
```

## MISP Configuration

Create a `.env` file in the project root directory:

```env
MISP_URL="https://misp.example.local"
MISP_KEY="your_api_key"
MISP_VERIFY_SSL="false"
MISP_TIMEOUT="15"
```

**Note**: the `.env` file contains an API key and should not be committed to the repository, avoid it by listing the `.env` file in *.gitignore*.

Application runtime settings can also be changed through the `config/app_config.json` file:

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

Meaning:

* `distribution` sets the MISP distribution level for the created or updated event,
* `analysis` sets the event analysis level,
* `publish_event` determines whether publish should be called after create/update.

## Usage

Show help:

```powershell
python app.py --help
```

Extract from a URL without importing into MISP:

```powershell
python app.py --url https://example.com/threat-report
```

Extract from a TXT file:

```powershell
python app.py --file .\samples\iocs.txt
```

Extract from a CSV file:

```powershell
python app.py --file .\samples\iocs.csv
```

Extract from a PDF file:

```powershell
python app.py --file .\samples\report.pdf
```

Save results to JSON:

```powershell
python app.py --url https://example.com/threat-report --save-json outputs\result.json
```

Import into MISP after confirmation:

```powershell
python app.py --file .\samples\report.pdf --push
```

When using the `--push` switch, the application first displays a preview of the extracted data and asks for confirmation. If it finds an existing event with the same source, it displays the differences and asks whether the existing event should be updated.

## TXT, CSV, and PDF Inputs

A TXT file is loaded as plain text without additional parsing. It is suitable, for example, for threat intelligence feeds and IoC lists with one entry per line.

A CSV file is read as text from all cells. Thanks to this, simple files in the following format also work:

```csv
type,value
url,hxxp://bad[.]example/payload
sha256,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

PDF files are read using the `pypdf` library. If a PDF contains only scanned images without a text layer, the application will have no text to extract. In that case, OCR must be applied before using this application.

## Allowlist and Exceptions

The project uses two configurable text files in the `config/` directory:

* `config/ioc_allowlist.txt` acts as a force include list. A value remains in the results even if the default filter would block it.
* `config/ioc_exceptions.txt` acts as a force exclude list. A value is discarded even if it would normally pass validation.

Line format:

```txt
domain:packages.npm.org
email-src:user@proton.me
url:hxxp://bad[.]example/path
ip-dst:203.0.113.10
md5:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Empty lines and lines starting with `#` are ignored. Values are normalized when loaded, so defanged URLs or domains are compared using their normalized form.

## Custom Regex

The project automatically loads custom regex patterns from the `config/ioc_custom_regex.txt` text file.

Line format:

```txt
btc-wallet:\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{20,60}\b
mutex:Global\\[A-Za-z0-9_-]+
npm-package:(?:^|[\s"'=:/])packages\.npm\.org\/((?:@[^\/\s"'<>]+\/)?[^\/\s"'<>?#]+)
```

Rules:

* the left side is the regex name and appears in the output as type `custom:<name>`,
* the name may contain lowercase letters, numbers, `-`, and `_`,
* the right side is a Python regex,
* empty lines and lines starting with `#` are ignored.

Custom regex matches:

* are displayed in the preview and JSON export,
* go through deduplication just like other types,
* are stored during MISP mapping as `text` attributes with the tag `ioc-type:custom:<name>`.

If a regex contains a capture group, the first non-empty group is stored in the result. If there is no group, the entire match is stored.

## IoC Section Extraction

For URL inputs, the application first tries to find a dedicated IoC section in the article, for example based on headings such as:

* `Indicators of Compromise`
* `Indicator of Compromise`
* `IoCs`
* `IoC`

If an IoC section is found and looks usable, extraction runs on it. Otherwise, the entire article is used.

Confidence scoring is tied to `extraction_scope`:

* `ioc_section` -> valid IoCs receive `high`,
* `full_article` and `file` -> scoring is more conservative.

## Behavior During MISP Import

A new event contains:

* source attribute:

  * `link` if the source is a web URL,
  * `text` if the source is a local file,
* source name as a `text` attribute,
* non-object IoCs as attributes,
* object-based IoCs as MISP objects:

  * `url`,
  * `domain-ip`,
  * `file`,
* *~~tags for source, validation, IoC type, and confidence~~*.

For duplicate sources, the application:

1. finds the existing event,
2. loads its attributes and objects,
3. displays new and already existing items,
4. after confirmation, adds only the new values.

Note: the application creates or updates the event, but currently does not call the final `publish`.

## Evaluation Scripts

The project also includes helper scripts for validating the solution:

Run evaluation on the fixture dataset:

```powershell
python tools\build_fixture_report.py
```

Outputs:

* `outputs/evaluation/fixture_report.json`
* `outputs/evaluation/fixture_report.md`

Run batch evaluation on a list of URLs/files:

```powershell
python tools\run_batch_manifest.py tools\sample_manifest.json
```

Outputs:

* `outputs/evaluation/batch_report.json`
* `outputs/evaluation/batch_report.md`

## Project Structure

```txt
app.py                      main CLI entry point
src/article_fetcher.py      loading and cleaning web articles
src/file_loader.py          loading TXT, CSV, and PDF files
src/ioc_extractor.py        regex-based IoC extraction
src/ioc_processor.py        validation, normalization, deduplication, allowlist, and exceptions
src/misp_mapper.py          mapping IoCs to MISP attributes
src/misp_exporter.py        creating and updating MISP events through PyMISP
src/json_exporter.py        export to JSON
src/metrics.py              metrics and evaluation
tests/                      unit tests and test data
tools/                      helper evaluation scripts
```

## Testing

Run tests:

```powershell
python -m unittest discover -s tests
```

Check compilation:

```powershell
python -m compileall app.py src tests
```

## Known Limitations

* URL extraction works reliably only on some websites. It depends on the HTML structure, availability of content in static HTML, and whether the article text can be read without browser rendering.
* Not all websites return the full article body in a regular HTTP request. As a result, some websites may not provide any IoCs even though they contain them when viewed in a browser.
* PDFs without a text layer require OCR outside the application.
* The CSV parser is generic and reads all cells as text.
* Neither the README nor the application currently implement an OpenCTI workflow.
* The application currently does not call `publish`; it only prepares or saves the event to MISP after user review.