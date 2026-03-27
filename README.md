<div id="top" align="center">

<!-- Shields Header -->
[![Contributors][contributors-shield]](https://github.com/franckferman/Memento-RTLO/graphs/contributors)
[![Stargazers][stars-shield]](https://github.com/franckferman/Memento-RTLO/stargazers)
[![License][license-shield]](https://github.com/franckferman/Memento-RTLO/blob/stable/LICENSE)

<!-- Logo -->
<a href="https://github.com/franckferman/Memento-RTLO">
  <img src="https://raw.githubusercontent.com/franckferman/Memento-RTLO/refs/heads/stable/docs/github/graphical_resources/Logo-without_background-Memento.png" alt="Memento-RTLO Logo" width="auto" height="auto">
</a>

<!-- Title & Tagline -->
<h3 align="center">Memento-RTLO</h3>
<p align="center">
    <em>File extension spoofing via the Right-to-Left Override Unicode character (U+202E).</em>
    <br>
    PowerShell-based red team and awareness tool demonstrating MITRE ATT&CK T1036.002.
</p>

</div>

---

## Table of Contents

<details open>
  <summary><strong>Click to collapse/expand</strong></summary>
  <ol>
    <li><a href="#about">About</a></li>
    <li><a href="#unicode-bidi-deep-dive">Unicode Bidi Deep Dive</a></li>
    <li><a href="#rtlo-attack-mechanics">RTLO Attack Mechanics</a></li>
    <li><a href="#mitre-attck-mapping">MITRE ATT&CK Mapping</a></li>
    <li><a href="#detection">Detection</a></li>
    <li><a href="#installation">Installation</a></li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#star-evolution">Star Evolution</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

---

## About

Memento-RTLO is a PowerShell tool that demonstrates **file extension spoofing** using the Right-to-Left Override (RTLO) Unicode control character (`U+202E`).

It renames or copies executable files (`.exe`, `.hta`, `.bat`, `.vbs`) so that their displayed extension appears benign (e.g., `.pdf`, `.jpeg`, `.txt`) while the underlying filesystem entry and operating-system behavior remain unchanged. The visual deception is produced entirely at the Unicode rendering layer, without modifying file content or metadata.

The project serves three audiences:

- **Red teamers** building phishing payloads for authorized engagements.
- **Security researchers** analyzing how operating systems and email clients render bidirectional filenames.
- **Blue teamers and trainers** demonstrating the attack to raise user awareness.

> This technique is well-documented and widely detected by modern endpoint protection platforms. It is not a sophisticated bypass. Its value is pedagogical.

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## Unicode Bidi Deep Dive

### The Unicode Bidirectional Algorithm (UBA)

The Unicode Standard defines the **Bidirectional Algorithm** (UAX #9) to handle mixed-direction text — documents that combine left-to-right (LTR) scripts such as Latin with right-to-left (RTL) scripts such as Arabic or Hebrew. The algorithm assigns a **bidi category** to every code point and then applies a set of rules to determine the visual order of characters on screen.

Key bidi categories relevant to this attack:

| Category | Name | Description |
|---|---|---|
| L | Left-to-Right | Standard Latin characters, digits in LTR context |
| R | Right-to-Left | Hebrew base characters |
| AL | Arabic Letter | Arabic base characters |
| AN | Arabic Number | Arabic-Indic digits |
| RLE | Right-to-Left Embedding | U+202B — open RTL embedding |
| LRE | Left-to-Right Embedding | U+202A — open LTR embedding |
| RLO | Right-to-Left Override | **U+202E** — force all following characters RTL |
| LRO | Left-to-Right Override | U+202D — force all following characters LTR |
| PDF | Pop Directional Formatting | U+202C — terminate the innermost embedding |

### U+202E: Right-to-Left Override

`U+202E RIGHT-TO-LEFT OVERRIDE` is a **format character** — it has zero width, produces no visible glyph, and is designed for use in contexts where a run of characters must be rendered right-to-left regardless of their intrinsic bidi properties.

Legitimate use cases include:

- Displaying a product code or part number written in a Latin script inside an otherwise RTL document.
- Embedding a URL that contains LTR punctuation inside Arabic body text.

Because it is a non-printing character, it is **invisible in most GUI contexts** — Windows Explorer, email clients, Outlook attachment lists, messaging applications, and web browsers all render the reversed characters without exposing the control character itself.

### Code Point Anatomy

```
U+202E
  Block    : General Punctuation (U+2000 - U+206F)
  Category : Cf  (Format character)
  Bidi     : RLO (Right-to-Left Override)
  Mirrored : No
  UTF-8    : E2 80 AE  (3 bytes)
  UTF-16LE : 2E 20     (2 bytes, BMP)
```

The three-byte UTF-8 sequence `0xE2 0x80 0xAE` is what appears in the raw bytes of any NTFS filename that embeds this character.

### Visual Reversal Mechanism

When `U+202E` is inserted at position *k* in a string, every character at positions *k+1* onward is rendered in reverse visual order by the bidi algorithm. The characters are stored in logical (memory) order unchanged; only the **rendering pipeline** reorders them.

Example — logical storage vs. visual presentation:

```
Logical bytes:  A n n e x e [U+202E] e p e j . e x e
                 ^-- LTR name --^    ^-- RTL rendering starts here --^

Visual output:  Annexe exe.jpeg
                         ^^^^^^ appears to be .jpeg extension
```

The file is an `.exe`. The filesystem, the kernel, and the process loader all see `exe.jpeg` reversed back to `gpej.exe` — but the **bidi display layer** shows `jpeg`. The operating system executes it as an EXE.

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## RTLO Attack Mechanics

### Filename Construction

The attack constructs a filename with the following logical structure:

```
<DisplayName> + U+202E + reverse(<SpoofExtension>) + <RealExtension>
```

Step by step for a target file `payload.exe` spoofed to appear as `Annexe.jpeg`:

1. Choose display name: `Annexe`
2. Choose spoof extension: `jpeg`
3. Reverse the spoof extension character by character: `gepj`
4. Append the real extension: `gepj.exe`
5. Insert `U+202E` between display name and reversed string: `Annexe[U+202E]gepj.exe`

The bidi algorithm renders `gepj.exe` right-to-left, producing the visual string `exe.jpeg` appended to `Annexe`, so the user sees **`Annexe exe.jpeg`**.

Windows Explorer also assigns the icon associated with `.jpeg` files to this entry (via shell association lookup on the **displayed** extension string), completing the visual deception.

### Supported File Types

| Real Extension | Spoof Options |
|---|---|
| `.exe` | `Annexe.jpeg`, `Document.pdf` |
| `.hta` | `Info.jpg`, `Fichier.txt` |
| `.bat` | `Note.txt`, `Liste.csv` |
| `.vbs` | `Script.txt`, `Email.eml` |

### Operating System Behavior

- **NTFS**: stores the exact logical byte sequence including `U+202E`. No sanitization occurs at the filesystem layer.
- **Windows Shell**: renders the filename through the DirectWrite/GDI bidi stack, showing the reversed visual form.
- **Process execution**: the Windows kernel resolves the filename using its logical byte sequence. When the user double-clicks the visually deceptive entry, the loader reads the real extension (`.exe`) and executes accordingly.
- **Linux (ext4/NTFS-3g)**: the character is valid in filenames. Terminal emulators with bidi support (e.g., mlterm, recent versions of GNOME Terminal with fribidi) will render the reversal.

### Delivery Vectors

The technique has been observed in the following delivery contexts:

- Email attachments (Outlook renders bidi filenames in the attachment pane).
- ZIP archives opened via Explorer or third-party archivers.
- Messenger file transfers (Telegram, WhatsApp Web).
- SMB shares browsed via Explorer.
- Malicious ISO/IMG mounts.

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## MITRE ATT&CK Mapping

### T1036.002 - Masquerading: Right-to-Left Override

| Field | Value |
|---|---|
| Tactic | Defense Evasion |
| Technique | T1036 - Masquerading |
| Sub-technique | T1036.002 - Right-to-Left Override |
| Platforms | Windows, Linux, macOS |
| Data Sources | File: File Metadata, File: File Creation, Process: Process Creation |

**ATT&CK description (paraphrased):** Adversaries may abuse the RTLO character to disguise the true file extension of a malicious payload. This sub-technique focuses on the Unicode bidirectional control character `U+202E`, which causes text following it to be displayed in reverse. When placed strategically in a filename, it causes the displayed extension to differ from the actual extension processed by the operating system.

### Related Techniques

| ID | Name | Relationship |
|---|---|---|
| T1566.001 | Spearphishing Attachment | Common delivery mechanism for RTLO-renamed payloads |
| T1204.002 | User Execution: Malicious File | Depends on the user clicking the spoofed file |
| T1036 | Masquerading (parent) | RTLO is one sub-technique of broader masquerading |
| T1027 | Obfuscated Files or Information | Conceptual overlap — non-content-level obfuscation |

### Real-World Usage

RTLO-based filename spoofing has been documented in:

- **APT28 (Fancy Bear)** spearphishing campaigns (2014-2016) targeting journalists and government officials.
- **Mahdi malware** (2012) — one of the early documented uses of RTLO in targeted attacks.
- Multiple commodity phishing kits distributed via email platforms.
- **FIN7** operational tooling in financial sector attacks.

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## Detection

### Filesystem-Level Detection

Scan filenames for the presence of Unicode bidi override/embedding characters:

| Code Point | Name | UTF-8 bytes |
|---|---|---|
| U+202A | Left-to-Right Embedding | `E2 80 AA` |
| U+202B | Right-to-Left Embedding | `E2 80 AB` |
| U+202C | Pop Directional Formatting | `E2 80 AC` |
| U+202D | Left-to-Right Override | `E2 80 AD` |
| U+202E | Right-to-Left Override | `E2 80 AE` |
| U+2066 | Left-to-Right Isolate | `E2 81 A6` |
| U+2067 | Right-to-Left Isolate | `E2 81 A7` |
| U+2068 | First Strong Isolate | `E2 81 A8` |
| U+2069 | Pop Directional Isolate | `E2 81 A9` |

PowerShell one-liner to scan the current directory for RTLO characters in filenames:

```powershell
Get-ChildItem -Recurse | Where-Object { $_.Name -match [char]0x202E } | Select-Object FullName
```

Python equivalent for cross-platform use:

```python
import os

BIDI_CONTROLS = {'\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
                 '\u2066', '\u2067', '\u2068', '\u2069'}

for root, dirs, files in os.walk('.'):
    for name in files:
        if any(c in name for c in BIDI_CONTROLS):
            print(os.path.join(root, name))
```

### SIEM / EDR Detection Rules

**Sigma rule concept (Windows file creation event):**

```yaml
title: RTLO Character in Filename
status: experimental
logsource:
  category: file_event
  product: windows
detection:
  selection:
    TargetFilename|contains: "\u202E"
  condition: selection
falsepositives:
  - Legitimate Arabic/Hebrew software with RTL product names (rare)
level: high
tags:
  - attack.defense_evasion
  - attack.t1036.002
```

**Windows Defender / MDE KQL:**

```kql
DeviceFileEvents
| where FileName contains "\u202E"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
```

### Email Gateway

Most enterprise email gateways (Proofpoint, Mimecast, Microsoft EOP) flag or strip attachments whose filename bytes contain `0xE2 0x80 0xAE`. Verify your gateway's Unicode normalization policy if RTLO files are a concern in your threat model.

### Antivirus Heuristics

Major AV vendors flag RTLO-named executables at the file-open/scan event layer. Detection is reliable on Windows when the file is written to disk. Network-level inspection varies by vendor.

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## Installation

### Prerequisites

- **Windows OS** (tested on Windows 10 and Windows 11).
- **PowerShell 5.1 or higher** (pre-installed on modern Windows).
- No external dependencies. Pure PowerShell.

### Getting Memento-RTLO

#### Option 1: One-liner download

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/franckferman/Memento-RTLO/stable/MementoRTLO.ps1 -OutFile MementoRTLO.ps1
```

#### Option 2: Clone via Git

```powershell
git clone https://github.com/franckferman/Memento-RTLO.git
```

#### Option 3: Download ZIP

1. Navigate to the GitHub repository.
2. Click `<> Code` then `Download ZIP`.
3. Extract to the desired location.

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## Usage

### Setup

Allow script execution for the current process (does not persist):

```powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process
```

### Basic Usage

```powershell
.\MementoRTLO.ps1 --file "C:\Path\to\payload.exe"
```

If `--choice` is omitted, the script presents an interactive menu of available spoof patterns for the detected extension.

Combined one-liner:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process; .\MementoRTLO.ps1 --file "C:\Path\to\payload.exe"
```

### Command-Line Reference

```
.\MementoRTLO.ps1 --file <path> [--choice <number>] [--replace] [--show-list] [--help]
```

| Option | Required | Description | Example |
|---|---|---|---|
| `--file <path>` | Yes | Path to the source file to spoof | `--file "C:\lab\test.exe"` |
| `--choice <n>` | No | Select spoof pattern by index (see `--show-list`) | `--choice 1` |
| `--replace` | No | Rename the original file in-place (default: create a copy) | `--replace` |
| `--show-list` | No | Print all available name/extension pairs and exit | `--show-list` |
| `--help` / `-help` / `/help` | No | Print help message and exit | `--help` |

### Examples

List available spoof patterns:

```powershell
.\MementoRTLO.ps1 --show-list
```

Spoof `payload.exe` as a PDF document (non-destructive copy):

```powershell
.\MementoRTLO.ps1 --file "C:\lab\payload.exe" --choice 2
```

Spoof `payload.exe` as a JPEG and rename the original in-place:

```powershell
.\MementoRTLO.ps1 --file "C:\lab\payload.exe" --choice 1 --replace
```

Spoof a VBS file as an email message:

```powershell
.\MementoRTLO.ps1 --file "C:\lab\dropper.vbs" --choice 2
```

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## Star Evolution

<a href="https://star-history.com/#franckferman/Memento-RTLO&Timeline">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=franckferman/Memento-RTLO&type=Timeline&theme=dark" />
    <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=franckferman/Memento-RTLO&type=Timeline" />
  </picture>
</a>

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## License

This project is licensed under the GNU Affero General Public License v3.0.
See the [LICENSE](https://github.com/franckferman/Memento-RTLO/blob/stable/LICENSE) file for the full terms.

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## Contact

[![ProtonMail][protonmail-shield]](mailto:contact@franckferman.fr)
[![LinkedIn][linkedin-shield]](https://www.linkedin.com/in/franckferman)
[![Twitter][twitter-shield]](https://www.twitter.com/franckferman)

<p align="right">(<a href="#top">Back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
[contributors-shield]: https://img.shields.io/github/contributors/franckferman/Memento-RTLO.svg?style=for-the-badge
[contributors-url]: https://github.com/franckferman/Memento-RTLO/graphs/contributors
[stars-shield]: https://img.shields.io/github/stars/franckferman/Memento-RTLO.svg?style=for-the-badge
[stars-url]: https://github.com/franckferman/Memento-RTLO/stargazers
[license-shield]: https://img.shields.io/github/license/franckferman/Memento-RTLO.svg?style=for-the-badge
[license-url]: https://github.com/franckferman/Memento-RTLO/blob/stable/LICENSE
[protonmail-shield]: https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=blueviolet
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=blue
[twitter-shield]: https://img.shields.io/badge/-Twitter-black.svg?style=for-the-badge&logo=twitter&colorB=blue
