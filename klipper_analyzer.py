#!/usr/bin/env python3
"""
Klipper Binary Analyzer
Analyzes a Klipper MCU firmware .bin file and produces an HTML report.
Usage: python3 klipper_analyzer.py <firmware.bin>
"""

import sys
import os
import zlib
import struct
import json
import html
from datetime import datetime

FLASH_BASE = 0x08000000

KNOWN_OFFSETS = [
    (0x0000,  0, "No bootloader (direct flash)"),
    (0x1000,  4, "Minimal / custom 4 KiB bootloader"),
    (0x2000,  8, "HID / stm32duino bootloader"),
    (0x3000, 12, "Creality K1 / K1 SE / K1 Max (GD32F303)"),
    (0x5000, 20, "DFU 20 KiB (uncommon)"),
    (0x7000, 28, "Creality/Klipper custom 28 KiB bootloader"),
    (0x8000, 32, "DFU 32 KiB standard"),
]

CRYSTAL_MAP = {
    72_000_000:  ("8 MHz",  "8 MHz × PLL×9 = 72 MHz — standard STM32F103/GD32F303"),
    64_000_000:  ("8 MHz",  "8 MHz × PLL×8 = 64 MHz"),
    48_000_000:  ("8 MHz",  "8 MHz × PLL×6 = 48 MHz"),
    24_000_000:  ("8 MHz",  "8 MHz × PLL×3 = 24 MHz"),
    120_000_000: ("8 MHz",  "8 MHz × PLL×15 = 120 MHz — GD32F303 high-speed mode"),
    180_000_000: ("12 MHz", "12 MHz × PLL×15 — likely STM32F4xx"),
    168_000_000: ("8/12 MHz", "STM32F4 — check PCB crystal"),
}


# ── Analysis functions ────────────────────────────────────────────────────────

def u32le(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def analyze_vector_table(data):
    msp   = u32le(data, 0)
    reset = u32le(data, 4)
    thumb = reset & 1
    addr  = reset & 0xFFFFFFFE
    msp_ok   = 0x20000000 <= msp   <= 0x20020000
    flash_ok = FLASH_BASE <= addr  <  FLASH_BASE + 0x80000
    return {
        'msp': msp, 'reset': reset, 'thumb': thumb,
        'reset_addr': addr, 'msp_ok': msp_ok, 'flash_ok': flash_ok,
    }


KNOWN_BL_OFFSETS = [0x0000, 0x1000, 0x2000, 0x3000, 0x5000, 0x7000, 0x8000]


def is_valid_vt(data, offset):
    """Check if a valid ARM Cortex-M vector table exists at this file offset."""
    if offset + 8 > len(data): return False
    msp   = u32le(data, offset)
    reset = u32le(data, offset + 4)
    msp_ok   = 0x20000000 <= msp   <= 0x20020000
    flash_ok = FLASH_BASE <= (reset & 0xFFFFFFFE) < FLASH_BASE + 0x80000
    return msp_ok and flash_ok and (reset & 1)


def find_link_base(data, dict_file_offset):
    """Find the true flash link base address using dictionary pointer cross-reference.

    This is the most reliable method across all toolchain versions and binary layouts.
    The Klipper config dictionary must be referenced by a pointer in the identify
    command handler. We try each known bootloader offset and see which one produces
    a dictionary flash address that is actually referenced in the binary.

    Falls back to vector table scanning (full flash images) or reset vector (last resort).
    """
    # Find where the vector table lives in the file
    vt_file_offset = 0
    if not is_valid_vt(data, 0):
        for off in KNOWN_BL_OFFSETS[1:]:
            if is_valid_vt(data, off):
                vt_file_offset = off
                break

    # Primary method: dictionary pointer cross-reference
    if dict_file_offset is not None:
        for bl_offset in KNOWN_BL_OFFSETS:
            link_base = FLASH_BASE + bl_offset
            dict_flash_addr = link_base + dict_file_offset - vt_file_offset
            needle = struct.pack('<I', dict_flash_addr)
            if data.count(needle) > 0:
                return link_base

    # Fallback 1: full flash image — vector table not at byte 0
    if vt_file_offset > 0:
        return FLASH_BASE + vt_file_offset

    # Fallback 2: reset vector rounded to 4 KiB page
    reset = u32le(data, 4) & 0xFFFFFFFE
    return reset & 0xFFFFF000


def extract_dictionary(data):
    """Scan for zlib magic and decompress Klipper config dictionary."""
    for i in range(4, len(data) - 10):
        if data[i] != 0x78 or data[i+1] not in (0x01, 0x5e, 0x9c, 0xda):
            continue
        try:
            d = zlib.decompressobj()
            text = d.decompress(data[i:]).decode('utf-8')
            obj = json.loads(text.strip())
            cfg = obj.get('config', obj)
            if any(k in cfg for k in ('MCU', 'CLOCK_FREQ', 'SERIAL_BAUD')):
                return obj, i
        except Exception:
            pass
    return None, None


def derive_crystal(clock_freq):
    if clock_freq is None:
        return None, None
    return CRYSTAL_MAP.get(int(clock_freq), (None, f"{int(clock_freq):,} Hz — crystal unknown"))


def offset_label(bl_offset):
    for off, kib, label in KNOWN_OFFSETS:
        if off == bl_offset:
            return kib, label
    return bl_offset // 1024, "Non-standard offset"


def hex_dump(data, start=0, count=64):
    rows = []
    for i in range(start, min(start + count, len(data)), 4):
        w = u32le(data, i)
        b = data[i:i+4]
        hex_str = ' '.join(f'{x:02X}' for x in b)
        addr = FLASH_BASE + i  # assuming application image
        note = ' ← MSP' if i == 0 else ' ← Reset' if i == 4 else ''
        rows.append((addr, hex_str, w, note))
    return rows


# ── HTML generation ───────────────────────────────────────────────────────────

CSS = """
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Barlow:wght@300;400;600;700&display=swap');
:root {
  --bg:#0a0c0f; --panel:#0f1318; --border:#1e2830; --border-hi:#2a3a48;
  --green:#00e5a0; --green-dim:#00a06e; --green-glow:rgba(0,229,160,0.12);
  --amber:#ffb340; --red:#ff4d6a; --blue:#4db8ff; --purple:#b06aff;
  --text:#c8d8e4; --text-dim:#5a7080;
  --mono:'Share Tech Mono',monospace; --sans:'Barlow',sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-weight:300;
     min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:40px 20px 60px;}
body::before{content:'';position:fixed;inset:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.07) 2px,rgba(0,0,0,.07) 4px);
  pointer-events:none;z-index:999;}
.header{text-align:center;margin-bottom:48px;}
.header h1{font-family:var(--mono);font-size:1.1rem;letter-spacing:.3em;color:var(--green);
           text-transform:uppercase;margin-bottom:8px;}
.header p{color:var(--text-dim);font-size:.8rem;letter-spacing:.1em;}
.filename-bar{background:var(--panel);border:1px solid var(--border);border-radius:4px;
              padding:10px 20px;font-family:var(--mono);font-size:.8rem;color:var(--amber);
              margin-bottom:32px;width:100%;max-width:900px;text-align:center;}
.card{background:var(--panel);border:1px solid var(--border);border-radius:6px;
      padding:24px 28px;margin-bottom:20px;width:100%;max-width:900px;}
.card-title{font-family:var(--mono);font-size:.7rem;letter-spacing:.25em;color:var(--green-dim);
            text-transform:uppercase;margin-bottom:20px;display:flex;align-items:center;gap:12px;}
.card-title::after{content:'';flex:1;height:1px;background:var(--border);}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px;}
.datum{background:#0a0e12;border:1px solid var(--border);border-radius:4px;padding:14px 16px;}
.datum-label{font-size:.6rem;letter-spacing:.2em;color:var(--text-dim);text-transform:uppercase;margin-bottom:6px;}
.datum-value{font-family:var(--mono);font-size:.95rem;color:var(--green);word-break:break-all;}
.datum-value.warn{color:var(--amber);}
.datum-value.info{color:var(--blue);}
.datum-value.purple{color:var(--purple);}
.datum-sub{font-size:.65rem;color:var(--text-dim);margin-top:4px;}
table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:.78rem;}
th{color:var(--text-dim);font-weight:400;text-align:left;padding:6px 8px;
   border-bottom:1px solid var(--border);font-size:.65rem;letter-spacing:.1em;}
td{padding:6px 8px;border-bottom:1px solid #111820;color:var(--text);}
tr.match td{color:var(--green);}
tr.match{background:var(--green-glow);}
.badge{display:inline-block;padding:2px 8px;border-radius:2px;font-size:.6rem;letter-spacing:.1em;}
.badge.match{background:rgba(0,229,160,.15);color:var(--green);border:1px solid var(--green-dim);}
.badge.no{background:#111;color:var(--text-dim);border:1px solid var(--border);}
.hi{color:var(--amber)!important;}
.addr{color:var(--text-dim);}
.verdict{border-radius:6px;padding:20px 24px;margin-bottom:20px;width:100%;max-width:900px;
         border:1px solid;}
.verdict.ok{border-color:var(--green-dim);background:var(--green-glow);}
.verdict.warn{border-color:var(--amber);background:rgba(255,179,64,.08);}
.verdict.error{border-color:var(--red);background:rgba(255,77,106,.08);}
.verdict-icon{font-family:var(--mono);font-size:1.2rem;margin-bottom:8px;}
.verdict-icon.ok{color:var(--green);}
.verdict-icon.warn{color:var(--amber);}
.verdict-icon.error{color:var(--red);}
.verdict-title{font-size:1rem;font-weight:600;margin-bottom:6px;}
.verdict-body{font-size:.82rem;color:var(--text-dim);line-height:1.6;}
.mc-row{display:flex;gap:12px;align-items:baseline;padding:8px 0;border-bottom:1px solid var(--border);}
.mc-row:last-child{border-bottom:none;}
.mc-key{font-family:var(--mono);font-size:.7rem;color:var(--text-dim);width:220px;flex-shrink:0;}
.mc-val{font-family:var(--mono);font-size:.85rem;color:var(--green);}
.mc-val.warn{color:var(--amber);}
.section-tag{font-family:var(--mono);font-size:.6rem;padding:2px 8px;border-radius:2px;margin-left:auto;
             background:rgba(0,229,160,.1);color:var(--green-dim);border:1px solid var(--border);}
pre{background:#060809;border:1px solid var(--border);border-radius:4px;padding:16px;
    font-family:var(--mono);font-size:.72rem;line-height:1.6;overflow-x:auto;white-space:pre-wrap;
    word-break:break-all;color:var(--text);margin-top:12px;}
.footer{color:var(--text-dim);font-size:.65rem;letter-spacing:.1em;margin-top:40px;text-align:center;}
"""

def render_html(filename, filesize, vt, link_base, bl_offset, dict_obj, dict_offset):
    h = html.escape
    kib, offset_label_str = offset_label(bl_offset) if bl_offset is not None else (None, None)
    cfg = dict_obj.get('config', dict_obj) if dict_obj else {}

    clock_freq   = cfg.get('CLOCK_FREQ')
    mcu_name     = cfg.get('MCU')
    serial_baud  = cfg.get('SERIAL_BAUD')
    serial_pins  = cfg.get('RESERVE_PINS_serial') or cfg.get('BUS_PINS_serial')
    initial_pins = cfg.get('INITIAL_PINS')
    version      = dict_obj.get('version') if dict_obj else None
    build_vers   = dict_obj.get('build_versions') if dict_obj else None

    crystal, crystal_note = derive_crystal(clock_freq)

    # Verdict
    if not vt['msp_ok'] or not vt['flash_ok'] or not vt['thumb']:
        verdict_cls   = 'error'
        verdict_icon  = '[!]'
        verdict_title = 'Invalid or unrecognised ARM Cortex-M image'
        verdict_body  = 'The vector table is not consistent with a valid ARM Cortex-M firmware. Verify this is a raw .bin — not ELF, DFU-wrapped, or encrypted.'
    elif dict_obj and bl_offset == 0x3000:
        verdict_cls   = 'ok'
        verdict_icon  = '[✓]'
        verdict_title = 'Valid Klipper firmware — Creality K1/K1 SE/K1 Max (GD32F303)'
        verdict_body  = (f"Config dictionary decoded. Bootloader offset confirmed: 12 KiB (0x3000). "
                         f"MCU: {mcu_name or '?'}. "
                         + (f"Crystal: {crystal} ({crystal_note}). " if crystal else "")
                         + (f"Serial: {serial_pins} at {int(serial_baud):,} baud." if serial_pins and serial_baud else ""))
    elif dict_obj:
        verdict_cls   = 'ok'
        verdict_icon  = '[✓]'
        verdict_title = f'Valid Klipper firmware — bootloader offset {f"0x{bl_offset:04X}" if bl_offset is not None else "unknown"} ({kib} KiB)'
        verdict_body  = (f"Config dictionary decoded. MCU: {mcu_name or '?'}. "
                         + (f"Crystal: {crystal}. " if crystal else "")
                         + (f"Serial: {serial_pins} at {int(serial_baud):,} baud." if serial_pins and serial_baud else ""))
    else:
        verdict_cls   = 'warn'
        verdict_icon  = '[~]'
        verdict_title = 'Valid ARM image — no Klipper dictionary found'
        verdict_body  = ('Vector table is valid and bootloader offset is readable, '
                         'but no embedded Klipper config dictionary was found. '
                         'This may be a bootloader binary or non-Klipper firmware.')

    # Build config dictionary HTML block separately to avoid nested f-string issues
    if not dict_obj:
        dict_section_html = '<p style="color:var(--text-dim);font-size:.82rem;">No Klipper config dictionary found. This may be a bootloader binary, an encrypted image, or a non-Klipper firmware. Vector table analysis above is still valid.</p>'
    else:
        clock_str = h(f"{int(clock_freq):,} Hz") if clock_freq else '—'
        baud_str  = h(f"{int(serial_baud):,}") if serial_baud else '—'
        raw_dict_html_inner = f'<pre>{h(json.dumps(dict_obj, indent=2))}</pre>'
        dict_section_html = (
            f'<div class="grid">'
            f'<div class="datum"><div class="datum-label">MCU</div>'
            f'<div class="datum-value">{h(str(mcu_name or chr(8212)))}</div></div>'
            f'<div class="datum"><div class="datum-label">Clock Frequency</div>'
            f'<div class="datum-value">{clock_str}</div></div>'
            f'<div class="datum"><div class="datum-label">Serial Baud</div>'
            f'<div class="datum-value">{baud_str}</div></div>'
            f'<div class="datum"><div class="datum-label">Serial Pins</div>'
            f'<div class="datum-value info">{h(str(serial_pins or chr(8212)))}</div></div>'
            f'<div class="datum"><div class="datum-label">Initial Pins</div>'
            f'<div class="datum-value purple">{h(str(initial_pins or chr(8212)))}</div></div>'
            f'<div class="datum"><div class="datum-label">Firmware Version</div>'
            f'<div class="datum-value info">{h(str(version or chr(8212)))}</div></div>'
            f'<div class="datum" style="grid-column:1/-1"><div class="datum-label">Build Toolchain</div>'
            f'<div class="datum-value" style="font-size:.75rem">{h(str(build_vers or chr(8212)))}</div></div>'
            f'</div>{raw_dict_html_inner}'
        )

    # Offset table rows
    offset_rows = ''
    for off, k, lbl in KNOWN_OFFSETS:
        match = (bl_offset == off)
        cls = ' class="match"' if match else ''
        badge = '<span class="badge match">✓ MATCH</span>' if match else '<span class="badge no">—</span>'
        offset_rows += f'<tr{cls}><td>0x{off:04X}</td><td>{k} KiB</td><td>{h(lbl)}</td><td>{badge}</td></tr>\n'

    # Raw dict (pretty printed, truncated for readability)
    raw_dict_html = ''
    if dict_obj:
        pretty = json.dumps(dict_obj, indent=2)
        raw_dict_html = f'<pre>{h(pretty)}</pre>'

    # Config key rows for menuconfig section
    def mc_row(key, val, cls=''):
        return f'<div class="mc-row"><div class="mc-key">{h(key)}</div><div class="mc-val {cls}">{h(str(val))}</div></div>\n'

    mc_rows = ''
    mc_rows += mc_row('Processor model', mcu_name or 'Unknown', '' if mcu_name else 'warn')
    if bl_offset is not None:
        mc_rows += mc_row('Bootloader offset', f'0x{bl_offset:04X}  ({kib} KiB) — {offset_label_str}')
    else:
        mc_rows += mc_row('Bootloader offset', 'Could not determine', 'warn')
    if crystal:
        mc_rows += mc_row('Crystal frequency', f'{crystal}', '')
        mc_rows += mc_row('  └ note', crystal_note, '')
    else:
        mc_rows += mc_row('Crystal frequency', 'Unknown — inspect PCB crystal', 'warn')
    if serial_pins:
        mc_rows += mc_row('Communication interface', f'Serial USART — pins {serial_pins}')
    if serial_baud:
        mc_rows += mc_row('Baud rate (SERIAL_BAUD)', f'{int(serial_baud):,}')
    if initial_pins:
        mc_rows += mc_row('Initial pins (INITIAL_PINS)', initial_pins)

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Klipper Binary Analysis — {h(filename)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="header">
  <h1>// Klipper Binary Analyzer</h1>
  <p>Static analysis report · Generated {now}</p>
</div>

<div class="filename-bar">{h(filename)}  ·  {filesize:,} bytes  ·  {filesize/1024:.1f} KiB</div>

<!-- Verdict -->
<div class="verdict {verdict_cls}">
  <div class="verdict-icon {verdict_cls}">{verdict_icon}</div>
  <div class="verdict-title">{verdict_title}</div>
  <div class="verdict-body">{h(verdict_body)}</div>
</div>

<!-- Vector Table -->
<div class="card">
  <div class="card-title">ARM Cortex-M Vector Table</div>
  <div class="grid">
    <div class="datum">
      <div class="datum-label">Stack Pointer (MSP)</div>
      <div class="datum-value {'warn' if not vt['msp_ok'] else ''}">0x{vt['msp']:08X}</div>
      <div class="datum-sub">{'✓ Valid SRAM range' if vt['msp_ok'] else '⚠ Not in expected SRAM range'}</div>
    </div>
    <div class="datum">
      <div class="datum-label">Reset Handler</div>
      <div class="datum-value {'warn' if not (vt['flash_ok'] and vt['thumb']) else ''}">0x{vt['reset']:08X}</div>
      <div class="datum-sub">{'✓ Thumb bit set · address in flash range' if vt['flash_ok'] and vt['thumb'] else '⚠ Invalid reset vector'}</div>
    </div>
    <div class="datum">
      <div class="datum-label">Bootloader Offset</div>
      <div class="datum-value {'warn' if bl_offset is None else ''}">{'0x{:04X}  ({} KiB)'.format(bl_offset, kib) if bl_offset is not None else '—'}</div>
      <div class="datum-sub">Derived from lowest flash address in binary (0x{link_base:08X})</div>
    </div>
    <div class="datum">
      <div class="datum-label">Link Base Address</div>
      <div class="datum-value info">{'0x{:08X}'.format(link_base) if link_base else '—'}</div>
      <div class="datum-sub">Lowest flash address referenced in binary</div>
    </div>
  </div>

  <br>
  <table>
    <thead><tr><th>Offset</th><th>Size</th><th>Bootloader</th><th>Match</th></tr></thead>
    <tbody>{offset_rows}</tbody>
  </table>
</div>

<!-- Config Dictionary -->
<div class="card">
  <div class="card-title">Klipper Config Dictionary
    <span class="section-tag">{'FOUND @ 0x{:04X}'.format(dict_offset) if dict_obj else 'NOT FOUND'}</span>
  </div>
  {dict_section_html}
</div>

<!-- make menuconfig Summary -->
<div class="card">
  <div class="card-title">make menuconfig Recommendations</div>
  {mc_rows}
</div>

<div class="footer">klipper binary analyzer · python edition · all analysis is local — no data transmitted</div>
</body>
</html>"""


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog='klipper_analyzer.py',
        description='Analyze a Klipper MCU firmware .bin file and produce an HTML report.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 klipper_analyzer.py firmware.bin
      Analyze firmware.bin, write firmware_analysis.html, open in browser.

  python3 klipper_analyzer.py firmware.bin --output report.html
      Write report to a specific path.

  python3 klipper_analyzer.py firmware.bin --no-browser
      Write report but do not open the browser (useful on headless systems).

  python3 klipper_analyzer.py noz0_*.bin mcu0_*.bin --no-browser
      Analyze multiple binaries in one invocation.
""",
    )
    parser.add_argument(
        'bin',
        metavar='firmware.bin',
        nargs='+',
        help='Path(s) to Klipper MCU firmware binary file(s).',
    )
    parser.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Output HTML report path. Defaults to <firmware>_analysis.html. '
             'Ignored when multiple input files are provided.',
    )
    parser.add_argument(
        '--no-browser',
        action='store_true',
        help='Do not open the report in the default browser after generating it.',
    )
    args = parser.parse_args()

    for bin_path in args.bin:
        if not os.path.isfile(bin_path):
            print(f"Error: file not found: {bin_path}", file=sys.stderr)
            sys.exit(1)

        with open(bin_path, 'rb') as f:
            data = f.read()

        print(f"Analyzing: {bin_path} ({len(data):,} bytes)")

        vt                    = analyze_vector_table(data)
        dict_obj, dict_offset = extract_dictionary(data)
        link_base             = find_link_base(data, dict_offset)
        bl_offset             = (link_base - FLASH_BASE) if link_base else None

        print(f"  MSP:          0x{vt['msp']:08X}  {'✓' if vt['msp_ok'] else '✗'}")
        print(f"  Reset:        0x{vt['reset']:08X}  {'✓' if vt['flash_ok'] and vt['thumb'] else '✗'}")
        print(f"  Link base:    0x{link_base:08X}" if link_base else "  Link base:    not found")
        print(f"  BL offset:    0x{bl_offset:04X}  ({bl_offset//1024} KiB)" if bl_offset is not None else "  BL offset:    unknown")
        print(f"  Dictionary:   {'found @ 0x{:04X}'.format(dict_offset) if dict_obj else 'not found'}")
        if dict_obj:
            cfg = dict_obj.get('config', dict_obj)
            print(f"    MCU:        {cfg.get('MCU')}")
            print(f"    CLOCK_FREQ: {cfg.get('CLOCK_FREQ')}")
            print(f"    SERIAL_BAUD:{cfg.get('SERIAL_BAUD')}")
            print(f"    Pins:       {cfg.get('RESERVE_PINS_serial') or cfg.get('BUS_PINS_serial')}")
            print(f"    InitPins:   {cfg.get('INITIAL_PINS')}")

        filename = os.path.basename(bin_path)
        report   = render_html(filename, len(data), vt, link_base or 0, bl_offset, dict_obj, dict_offset)

        if args.output and len(args.bin) == 1:
            out_path = args.output
        else:
            out_path = bin_path.replace('.bin', '_analysis.html')
            if out_path == bin_path:
                out_path = bin_path + '_analysis.html'

        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(report)

        print(f"  Report: {out_path}")

        if not args.no_browser:
            try:
                import webbrowser
                webbrowser.open(f'file://{os.path.abspath(out_path)}')
            except Exception:
                pass

        print()


if __name__ == '__main__':
    main()
