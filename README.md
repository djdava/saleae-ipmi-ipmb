# IPMI / IPMB for Saleae Logic 2

**Author:** David Hernandez Navalon · **License:** MIT

A Python High-Level Analyzer (HLA) that turns the built-in I2C analyzer output
into readable IPMI/IPMB annotations, including IPMB-L and selected PICMG commands.
Keep command names visible at a glance, or enable decoded payload summaries and
inspect individual fields in Logic's data table.

```text
Get Device ID [REQ]
Read FRU Data [REQ] | FRU=2; offset=32; count=4
Get Sensor Reading [RSP: OK (0x00)] | sensor=42; raw=0x80 (unscaled)
```

Examples and tests use synthetic data. This repository contains no recorded
traffic, device logs, deployment configuration or external capture dependencies.
The extension only analyzes traffic; it does not transmit anything to the bus.

## Install locally

1. Download or clone this repository to a folder you intend to keep.
2. Open **Extensions** in Logic 2, click **+**, and choose
   **Load Existing Extension**. Select this folder's `extension.json`.
3. Open or record a capture and add the built-in **I2C** analyzer with the
   appropriate SDA and SCL channels for your capture.
4. Add **IPMI / IPMB** from **Analyzers → +**, choosing that I2C analyzer as
   its **Input Analyzer**.

No external Python packages, separate Python installation, or capture file
parser are required to use the extension. It uses HLA API 1.0.0 and Python
3.8-compatible syntax. The analyzer has been used with Logic **2.4.48**;
compatibility with every Logic release and command variant is not guaranteed.

### Updating a local installation

Replace the files in the same folder and select **Reload Source Files** from
the analyzer menu. If new settings are missing, remove and re-add the HLA,
keeping its input I2C analyzer. Restart Logic if helper modules remain cached.

## Display settings

The **Display** setting controls the message header:

- **Compact:** command name, request/response, and response completion code.
- **Detailed:** also show source/destination IPMB addresses and sequence number.

The independent **Payload display** setting controls the appended payload:

| Setting | Waveform annotation |
|---|---|
| Inspector only (default) | Keep the compact command label; inspect data in the table. |
| Decoded summary | Append interpreted parameters/results; fall back to hex when unsupported. |
| Hex bytes | Append the raw payload in requests and responses. |

Appended text is shortened to 120 characters to avoid clutter; the data table
and exports retain the complete values. Two HLA instances can share the same
I2C input, for example one compact row and one row with payload summaries.

## Inspecting fields

Hover over a waveform annotation and use Logic's displayed shortcut to jump
to its **Data Table** row. The HLA API does not provide a custom expandable
panel per annotation: this extension uses Logic's native table instead.
Right-click column headers to hide fields you do not need.

Useful output columns:

| Column | Meaning |
|---|---|
| `payload_summary` | Full decoded summary. |
| `decoded` | All interpreted fields as readable text. |
| `field_*` | Individual typed payload fields, suitable for searching and export. |
| `payload`, `raw` | Original payload and complete IPMB message bytes, in hex. |
| `payload_status`, `payload_notes` | Interpretation status and limitations. |
| `request_match` | Whether a response could be associated with a request. |
| `field_request_*` | Parameters inherited from a matched, decoded request. |
| `response_latency_ms` | Time between request and response **starts**, not internal execution time. |

Payload status values are `decoded`, `partial` (uninterpreted trailing bytes),
`raw` (unsupported decoder), `malformed`, `untrusted`, or `response_error`.
Response payloads exclude the completion code; Group Extension IDs remain
part of the original hex payload.

## Coverage

### Command names

The catalog contains **250 identifiers**: 182 Chassis, Bridge/ICMB, Sensor/Event,
Application, Storage and Transport commands, plus 68 PICMG commands including
ATCA, AMC.0, MicroTCA and HPM.1/2/3. These identifiers do not imply that a
particular controller supports a command or that it is applicable to IPMB-L.

PICMG names require request NetFn `0x2C` **and Group ID `0x00`**. Other group
extensions, such as DCMI, are not mislabeled as PICMG. Firmware Update NetFn
`0x08`, OEM commands and uncatalogued identifiers retain numeric codes and raw
payload rather than guessed names. This is not a universal private/OEM catalog.

Responses can be named from their own headers without a preceding request.
Completion codes use generic descriptions; command-specific and OEM-specific
codes retain their numeric values without an invented explanation.

### Decoded payloads

Payload decoders cover **23 command identifiers**, in each applicable direction:

| Commands | Interpreted information |
|---|---|
| Get Device ID | Device/revision, firmware/IPMI version, manufacturer/product and capabilities. |
| Set/Get Event Receiver, Platform Event | Receiver/LUN, `0xFF` event-generation disable, sensor, event type/direction and event bytes. |
| Get FRU Inventory Area Info, Read/Write FRU Data | Size/access mode, FRU ID, offset, counts and hex data. |
| Get Device SDR Info; Reserve/Get Device SDR; Reserve/Get SDR | Count selector, population, reservation, record ID, offset, next ID and fragment bytes. |
| Get Sensor Reading | Requested sensor, raw reading, availability, scanning/events and state bytes. |
| PICMG Properties, FRU Control, Set FRU Activation, Set/Get Activation Policy, Get Device Locator Record ID | Version, FRU ID, action, masks/locks and record ID. |
| PICMG Get FRU LED Properties, Get LED Color Capabilities, Set/Get FRU LED State | FRU/LED ID, colors, function, local/override state and blink durations. |

Command-name coverage is broader than payload coverage. HPM, encapsulated
Send/Get Message traffic, OEM payloads and other unsupported layouts remain hex.

## Integrity and limitations

- Both IPMB checksums, I2C NACKs and reported I2C errors are checked. Transport
  warnings produce `UNVERIFIED` annotations; a NACKed address without a command
  body is not identified as a command.
- Successful completion (`OK`) is not proof of integrity or physical execution
  of a requested action. Payload interpretation is suppressed on transport errors,
  checksum failures and nonzero response completion codes.
- Short supported payloads are `malformed`, not partially decoded as complete
  values. Extra bytes are retained and marked `partial`. Summary mode highlights
  malformed payloads while inspector-only mode preserves the short labels.
- FRU offsets stay in access units until byte/word addressing is known. FRU/SDR
  fragments are not reassembled into inventories or full records. Sensor readings
  are not converted to physical units, signed values or threshold/discrete states
  without the required metadata. No hot-swap state is inferred from event bytes.
- Request matching checks reversed addresses/LUNs, NetFn, command, sequence and
  group/OEM prefix. It is limited to a five-second window and 128 pending requests
  per HLA instance. Ambiguous sequence reuse supplies no request context.
- Detailed labels use **8-bit IPMB addresses**. For example, IPMB address `0x40`
  corresponds to 7-bit I2C address `0x20`; both forms are available in table fields.
  The extension does not assume a hardware role for any address.
- IPMB requests **and** responses use I2C writes. I2C reads are marked as not
  IPMB. Annotations are emitted at STOP or the next START. If a capture ends
  before either arrives, the final transaction has no annotation: there is no
  end-of-capture callback in this HLA interface. Orphan data is ignored.
- A 1024-byte defensive buffer limit is not a statement of permitted IPMB length.

## Development and tests

From the repository root, with Python 3.8 or newer:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

There are **47 standalone tests**. They include request/response naming for
all 250 identifiers, payload layout checks, 1610 reproducible synthetic
command/direction/length combinations, corruption/truncation checks, display
modes and bounded multimaster request matching. Tests use a small Saleae API
stub: they are not a substitute for verifying installation and UI behavior
inside Logic, or for checking a command against its normative specification.

To extend coverage, add a synthetic test and a referenced decoder in
`payloads.py`, or extend `commands.py` for command names. Preserve original
bytes and explicit fallback when a format cannot safely be interpreted.

## References

Command identifiers and payload layouts were checked against public
implementations, without incorporating their dissector code. Not every
identifier has been verified against its normative specification.

- [Saleae HLA documentation](https://support.saleae.com/support/extensions-api/extensions/high-level-analyzer-extensions)
- [I2C frame API](https://support.saleae.com/support/extensions-api/hla-frame-format-reference/i2c-analyzer)
- [Extension format](https://support.saleae.com/support/extensions-api/extensions/extension-file-format)
- [Publishing an extension](https://support.saleae.com/support/extensions-api/extensions/publish-an-extension)
- [Wireshark dissectors](https://github.com/wireshark/wireshark/tree/master/epan/dissectors):
  `packet-ipmi-{chassis,bridge,se,app,storage,transport,picmg}.c` and generic
  completion codes in `packet-ipmi.c`.
- [ipmitool PICMG identifiers](https://github.com/ipmitool/ipmitool/blob/master/include/ipmitool/ipmi_picmg.h)
- [HPE Set Event Receiver documentation](https://support.hpe.com/hpesc/public/docDisplay?docId=a00018321en_us&page=GUID-D7147C7F-2016-0901-06CE-000000000620.html)

Independent community extension; not endorsed by Saleae.
