<div align="center">

<a href="https://github.com/franckferman/Memento-RTLO">
  <img src="https://raw.githubusercontent.com/franckferman/Memento-RTLO/refs/heads/stable/docs/github/graphical_resources/Logo-without_background-Memento.png" alt="Memento-RTLO" width="300">
</a>

<h3>Memento-RTLO</h3>
<p><em>File extension spoofing via the Right-to-Left Override Unicode character (U+202E).</em><br>
PowerShell-based red team and awareness tool demonstrating MITRE ATT&CK T1036.002.</p>

</div>

---

## About

Memento-RTLO is a PowerShell tool that demonstrates **file extension spoofing** using the Right-to-Left Override (RTLO) Unicode control character (`U+202E`).

It renames or copies executable files (`.exe`, `.hta`, `.bat`, `.vbs`, `.ps1`) so that their displayed extension appears benign (e.g., `.pdf`, `.jpeg`, `.txt`, `.docx`) while the underlying filesystem entry and operating-system behavior remain unchanged. The visual deception is produced entirely at the Unicode rendering layer, without modifying file content or metadata.

---

## Demo

<div align="center">
  <img src="https://raw.githubusercontent.com/franckferman/Memento-RTLO/stable/docs/github/screenshots/explorer_spoofed.png" alt="RTLO spoofed files in Windows Explorer" width="700">
  <br><em>Windows Explorer — .exe / .hta / .bat / .vbs / .ps1 files spoofed as .pdf, .csv, .jpeg, .txt, .png (extensions hidden, default Windows setting)</em>
</div>

---

## Usage

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/franckferman/Memento-RTLO/stable/MementoRTLO.ps1 -OutFile MementoRTLO.ps1
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process
```

### Command-Line Reference

```
.\MementoRTLO.ps1 --file <path> [--choice <N>] [--replace] [--dry-run] [--bidi-char <mode>]
.\MementoRTLO.ps1 --file <path> --name <basename> --fake-ext <ext> [--replace] [--dry-run]
.\MementoRTLO.ps1 --show-list [--file <path>]
```

| Option | Description |
|---|---|
| `--file <path>` | Source file to spoof (`.exe` / `.hta` / `.bat` / `.vbs` / `.ps1`) |
| `--choice <N>` | Select a predefined pattern by global index (see `--show-list`) |
| `--name <basename>` | Custom output base name, bypasses predefined patterns |
| `--fake-ext <ext>` | Fake extension to display, e.g. `pdf`, `jpg` (requires `--name`) |
| `--replace` | Rename in-place instead of creating a copy |
| `--dry-run` | Preview the output filename without writing any file |
| `--show-list` | List all available patterns; combine with `--file` to filter by extension |
| `--bidi-char <mode>` | Override character: `rlo` (default, U+202E) \| `rli` (U+2067) \| `rle` (U+202B) |
| `--help` | Show help and exit |

### Examples

```powershell
# List all predefined patterns
.\MementoRTLO.ps1 --show-list

# List patterns for .exe files only
.\MementoRTLO.ps1 --show-list --file payload.exe

# Preview output filename without writing (dry run)
.\MementoRTLO.ps1 --file payload.exe --choice 1 --dry-run

# Spoof payload.exe as a PDF document (copy)
.\MementoRTLO.ps1 --file payload.exe --choice 1

# Rename in-place as a JPEG
.\MementoRTLO.ps1 --file payload.exe --choice 4 --replace

# Custom name: appear as cv_franck.pdf (actually .hta)
.\MementoRTLO.ps1 --file cv_franck.hta --name cv_franck --fake-ext pdf

# Custom name with dry-run preview
.\MementoRTLO.ps1 --file rapport.exe --name Rapport_annuel --fake-ext pdf --dry-run
```

---

## Unicode Bidirectional Deep Dive

The Unicode Standard defines the **Bidirectional Algorithm** (UAX #9) to handle mixed-direction text. Documents combining left-to-right (LTR) scripts such as Latin with right-to-left (RTL) scripts such as Arabic or Hebrew require the algorithm to assign a bidi category to every code point and determine the visual rendering order.

Key categories relevant to this technique:

| Category | Name | Description |
|---|---|---|
| L | Left-to-Right | Standard Latin characters |
| RLO | Right-to-Left Override | **U+202E**: forces all following characters RTL |
| RLE | Right-to-Left Embedding | U+202B: opens an RTL embedding level |
| LRO | Left-to-Right Override | U+202D: forces all following characters LTR |
| PDF | Pop Directional Formatting | U+202C: terminates the innermost embedding |

### U+202E: Right-to-Left Override

`U+202E` is a **format character**, zero-width with no visible glyph. It forces every character following it to be rendered right-to-left regardless of intrinsic directionality. Because it is non-printing, it is **invisible in most GUI contexts**: Windows Explorer, Outlook attachment panes, messaging apps, and web browsers render the reversed characters without exposing the control character.

```
U+202E
  Block    : General Punctuation (U+2000-U+206F)
  Category : Cf (Format character)
  Bidi     : RLO (Right-to-Left Override)
  UTF-8    : E2 80 AE  (3 bytes)
  UTF-16LE : 2E 20     (2 bytes)
```

### Visual Reversal

When `U+202E` is inserted at position *k*, every character from *k+1* onward is rendered in reverse visual order. Storage order is unchanged; only the rendering pipeline reorders them.

```
Logical:  A n n e x e [U+202E] . g e p j . . e x e
                               ^-- RTL rendering starts here

Visual (extensions hidden):  Annexe.jpeg
```

The file is an `.exe`; the kernel reads the real extension and executes it accordingly.

---

## RTLO Attack Mechanics

### Filename Construction

```
<DisplayName> + U+202E + reverse(.<SpoofExtension>) + <RealExtension>
```

Step by step, `payload.exe` spoofed to appear as `Annexe.jpeg`:

1. Display name: `Annexe`
2. Spoof extension with leading dot: `.jpeg`, reversed: `gepj.`
3. Append real extension: `gepj..exe`
4. Insert `U+202E`: `Annexe[U+202E]gepj..exe`
5. With extensions hidden, Explorer renders `gepj.` via RTLO as `.jpeg`, giving **`Annexe.jpeg`**

> The leading dot of the spoof extension must be included before reversing so the separator dot appears on the correct side after RTLO rendering.

### Supported File Types

| Real Extension | Predefined Patterns |
|---|---|
| `.exe` | `Rapport_trimestriel.pdf`, `Annexe_contrat.pdf`, `Devis_client.pdf`, `Photo_reunion.jpeg`, `Scan_document.jpg`, `Logo_societe.png`, `Note_interne.txt` |
| `.hta` | `Info_reunion.jpg`, `Bilan_annuel.pdf`, `Fichier_partage.txt`, `Capture_ecran.png` |
| `.bat` | `Liste_contacts.csv`, `Note_reunion.txt`, `Instructions_setup.txt`, `Export_donnees.csv` |
| `.vbs` | `Script_backup.txt`, `Email_client.eml`, `Rapport_audit.pdf` |
| `.ps1` | `Config_systeme.txt`, `Rapport_securite.pdf`, `Donnees_export.csv`, `Document_interne.docx` |

Use `--name` and `--fake-ext` for fully custom filenames not in the predefined list.

### Operating System Behavior

- **NTFS**: stores the exact logical byte sequence including `U+202E`. No sanitization at the filesystem layer.
- **Windows Shell**: renders filenames through DirectWrite/GDI bidi stack, showing the reversed visual form.
- **Process execution**: the kernel resolves filenames by logical byte sequence. The loader reads the real extension and executes accordingly.
- **Extensions visibility**: the technique relies on Windows hiding known file extensions (the default setting). When extensions are shown, the real extension appears reversed in the visual name.

---

## License

This project is licensed under the GNU Affero General Public License v3.0.
See the [LICENSE](https://github.com/franckferman/Memento-RTLO/blob/stable/LICENSE) file for the full terms.

---

## Contact

[![ProtonMail][protonmail-shield]](mailto:contact@franckferman.fr)
[![LinkedIn][linkedin-shield]](https://www.linkedin.com/in/franckferman)
[![Twitter][twitter-shield]](https://www.twitter.com/franckferman)

[protonmail-shield]: https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=blueviolet
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=blue
[twitter-shield]: https://img.shields.io/badge/-Twitter-black.svg?style=for-the-badge&logo=twitter&colorB=blue
