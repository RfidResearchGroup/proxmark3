# ePassport

An ePassport (eMRTD) viewer: reads a passport chip through the Proxmark3 and
renders it as a passport data page.

Everything runs **offline**. No telemetry, no cloud OCR, no network calls of
any kind — every font and asset is bundled.

```
./ePassport.py                                   # normal use
./ePassport.py --dump DIR                       # open a saved dump, no hardware
./ePassport.py --dry-run pm3.log --dump DIR     # replay a session you recorded
./ePassport.py --help
```

`ePassport.py` is a plain launcher script — run it directly (it has a shebang) or with `python3`, from anywhere, by path or
from a symlink; there is nothing to install and no `PYTHONPATH` to set. If a
dependency is missing it says which one, which interpreter it used, and the
exact command to fix it.

It needs an interpreter that has the requirements. With a virtualenv, either
activate it first or point at it directly:

```bash
/path/to/venv/bin/python ./ePassport.py
```

---

## Install

```bash
python3 -m pip install -r requirements.txt
```

Kivy is required. Everything else is optional and the app degrades with a
message telling you what to install:

| Missing | What stops working |
|---|---|
| `opencv-python-headless` | the Scan screen (camera) |
| `pytesseract` + the `tesseract-ocr` binary | MRZ OCR — manual entry still works |
| `Pillow` / `glymur` | portrait decoding (DG2 is usually JPEG2000) |
| `asn1crypto` / `cryptography` | EF_SOD inspection and the DG hash table |

For the best OCR accuracy install the OCR-B or `mrz` traineddata; the app picks
it up automatically and falls back to `eng` with a character whitelist.

`sudo apt install xclip` enables Kivy's cut-buffer support. The app filters
the noisy `[CRITICAL] [Cutbuffer]` complaint either way; nothing depends on it.

## Relationship to proxmark3

This app **does not modify the proxmark3 tree**. The only coupling is the `pm3`
CLI, invoked in one-shot command mode:

```
pm3 -c "hf emrtd dump -n <DOCNUM> -d <YYMMDD> -e <YYMMDD> --dir <outdir>"
pm3 -c "hf emrtd info --dir <existing dump>"     # offline mode
```

The binary is located via `$PM3_BIN` → the configured path → `PATH` → `~/pm3/pm3`
→ the `./pm3` wrapper of an enclosing proxmark3 source tree.

The country-name table in `emrtd/countries.py` is **generated** from the
proxmark3 client's own ISO-3166 table (`fdxbCountryMapping` in
`client/src/cmdlffdxb.c`). Regenerate it with:

```bash
python3 tools_gen_countries.py ../../client/src/cmdlffdxb.c
```

### Authentication

| You have | Enter | What runs |
|---|---|---|
| The MRZ | document number + both dates, or line 2 | PACE with the MRZ, falling back to BAC |
| The CAN | the number printed on the data page | `--can` (PACE only) |

The **CAN** is the short number printed on the data page — usually 6 digits.
It is a PACE password, so it is mutually exclusive with the MRZ, and BAC can
never use it. The Authentication dropdown forces `--pace` or `--bac` when you
want to test one path; leave it on Automatic otherwise.

Wrong CANs are counted by the chip and the password will eventually block, so
that failure is called out separately from a wrong MRZ.

### Two things worth knowing about `hf emrtd`

- **All three of `-n/-d/-e` must be supplied**, or the client silently drops to
  no-BAC mode and fails on any protected passport. The app refuses a partial
  triple rather than passing it on.
- **The `pm3` wrapper blocks forever** waiting for a device when none is
  attached. The app watches for that line and reports "No Proxmark3 found"
  immediately instead of sitting on the timeout.

## Using it

1. **Scan** the MRZ with a camera, or **type** the three values. A full 44-char
   MRZ line 2 takes precedence and is passed as `-m`, which avoids
   field-splitting mistakes.
2. **Read** — pm3 runs on a worker thread and streams into the LOG tab, with a
   determinate progress bar and a Cancel that actually kills the process.
3. The dump is parsed from the **binaries** (BER-TLV), never scraped from
   `hf emrtd info` stdout, and rendered as a data page.

Tabs across the top: `DATA PAGE` · `PERSONAL` (DG11) · `ISSUER` (DG12) ·
`SECURITY` (SOD/DG14/DG15) · `FILES` · `LOG`.

### Output

The app is quiet by default. Kivy 2.3 takes its log level from
`~/.kivy/config.ini`, which is shared with every other Kivy app on the machine,
so rather than rewrite that the app drops Kivy's console handler and installs
its own for warnings and above. pytesseract (which logs a full tesseract
command line per frame), OpenCV and its V4L2 backend are quietened the same
way. `-v` puts all of it back.

### Resizing

The page is laid out **once** at a fixed resolution and then drawn scaled, so a
resize costs a matrix multiply rather than a full re-flow. Re-flowing it on
every resize event re-rendered every label and regenerated the security print
several times a frame, which made dragging a window edge crawl and the contents
jitter as text reflowed under the cursor.

Measured over twenty resize steps:

| | Before | After |
|---|---|---|
| Page widget redraws per step | 21 | 0 |
| Label re-renders per step | 65 | 11 (window chrome only) |
| Time in text rendering | 182 ms | 10 ms |

Two supporting fixes: redraws are coalesced onto a `Clock` trigger so `pos` and
`size` changing separately cannot cause three redraws in one frame, and MRZ
glyphs are cached per (character, size) — an MRZ is ~90 characters drawn from
an alphabet of 37, so it was building ninety textures to show at most
thirty-seven distinct ones.

### Why a document may not fill the window

Both formats are always scaled as large as they fit without distorting, so
neither is ever "shrunk" — but a document and a window are different shapes,
and only one of the two dimensions can fill. Whichever document is closer to
the window's shape uses more of it:

| Window content shape | Passport (1.42) | Card (1.59) |
|---|---|---|
| 1.61 (wide) | 88% wide, 100% tall | 99% wide, 100% tall |
| 1.42 (the default) | **100% wide, 100% tall** | 100% wide, 90% tall |
| 2.59 (very wide) | 55% wide, 100% tall | 61% wide, 100% tall |

The default window is sized so its **content area comes out at the reference
document's own 125:88**, so a passport fills it exactly on first run. Stretch
the window wide and both documents will letterbox at the sides; that is the
shape mismatch, not the app giving up on the space.

### Small windows

The minimum window is 760x520 and the app remembers the size you leave it at.
Everything is built to survive that:

- the passport page scales as a unit and keeps its aspect;
- the tab strip shares its width rather than claiming fixed slots;
- the FILES table uses proportional columns, so the state column does not fall
  off the edge;
- the hex viewer fits **16, 8 or 4 bytes per row** to whatever width the pane
  has, because a hex dump must not wrap.

### Speed

An MRZ scan settles in roughly a second. What that took:

| Change | Effect |
|---|---|
| Cheap pre-gate before OCR (`looks_like_text`) | a badly framed strip costs ~0.3 ms instead of ~400 ms |
| Skip frames already processed | no repeat OCR of an identical frame |
| Pace the loop instead of adding to it | the interval no longer stacks on top of the work |
| Cache the language lookup | it shelled out to tesseract every frame |
| Stop escalating variants with no signal | 2 passes instead of 3 on hopeless frames |
| Remember the last winning variant | dim lighting costs 1 pass, not 3 |

Measured on a live camera: mean OCR pass 381 ms → 163 ms, time to acceptance
3.1 s → 1.3 s, with accuracy unchanged on the synthetic bench.

The gate runs *after* deskew — it measures horizontal bands of ink, and tilted
text smears those bands together.

An in-process binding (`tesserocr`) is ~3× faster per call than re-launching
the tesseract binary, and was tried. It is **not** used: the PyPI wheel bundles
its own leptonica, and pairing that with a system `tessdata` directory hung
indefinitely mid-recognition. A backend that can wedge the OCR thread is worse
than a slower one.

### Cameras

The Scan screen enumerates capture devices by name from
`/sys/class/video4linux` — without opening them, because opening a device is
disruptive if something else is using it.

- **No camera**: the screen says so and offers **Rescan for devices**. Manual
  entry is always available and works just as well.
- **One or more**: a dropdown lists them by name (`0: IPEVO Ziggi-HD Plus`).
  The choice is remembered.

Linux commonly exposes several `/dev/videoN` nodes for one physical camera,
only one of which delivers frames — `isOpened()` returns true for the others.
The app therefore treats a successful *read* as the test, and falls back to a
neighbouring index automatically. **Rescan** probes every device to label the
dead ones `(no frames)`; it stops the preview first so the probe and the
capture thread do not fight over the device.

Only line 2 is needed for BAC, so the scan accepts a lone line 2 when its five
check digits — composite included — all pass.

### What a "valid" MRZ scan does and does not prove

A scan is accepted only when every check digit validates **and** two
consecutive frames agree. That still does not prove the document number is
right. The 7-3-1 checksum is taken modulo 10 and its weights are coprime with
10, so swapping a character for one whose value differs by a multiple of 10
leaves every check digit — composite included — unchanged. The blind pairs are
`L`/`1`, `S`/`8`, `G`/`6`, `Z`/`5`, `I`/`8`, `D`/`3` … which are exactly the
swaps OCR is most likely to make.

That is why a scan **fills the entry form and stops** rather than starting a
read, and why the form flags the document number for a second look. If BAC
then fails, the document number is the first thing to check.

(Confusions that are *not* blind, such as `O` read as `0` in a country code,
are repaired automatically by position before validation.)

### Drawing the page

A TD1 is an ID-1 card (85.6 x 54 mm), not a small passport data page
(125 x 88 mm), and its three-line MRZ takes about a quarter of its height
against an eighth for a passport's two lines. The page is drawn at whichever
shape the document really is.

**Two scale modes**, because you cannot have both at once. OCR-B is a fixed
2.54 mm pitch on every format, but a character is 2.97% of a card's width and
only 2.03% of a passport's — so a card's MRZ is inherently half again as large
relative to its own document:

| Mode | What it gives you | What it costs |
|---|---|---|
| **Fit window** (default) | every document fills the window | a card's MRZ prints ~1.5x a passport's on screen |
| **True size** | MRZ print identical across formats, as in the hand | a card is drawn two thirds the width, leaving margins |

Opening a dump re-fits the page for whatever format it turns out to be, so the
button is a preference you set once, not something to press after every load.
The toolbar button swaps them and the choice is remembered. It is labelled
with the **action**, like the chrome button beside it: reading "Fit window"
means clicking will fit the window, so you are currently at true size. A
passport looks identical either way; only formats smaller than the reference
page differ.

Within the band, the MRZ block is sized to fit in **both** directions — the
smaller of the width- and height-derived sizes wins, and a block that does not
fill the width is centred. Fitting the width alone pushed a card's MRZ out over
the fields above it; leaving a full line of air between rows then shrank it
until it no longer reached the margins.

The **portrait** is sized from the page width and the real 35 x 45 photo shape,
capped against the space above the band — a fraction of page height alone made
it swallow a short card. The frame keeps the photo aspect whichever constraint
binds, so an image never sits letterboxed in white bars.

The guilloche is generated procedurally (superimposed hypotrochoids at low
alpha) — nothing is traced from a real document's security print. It is clipped
to the printed frame **geometrically**, with a Liang-Barsky segment clip, not
with a stencil: this widget can sit inside another `StencilView`, and Kivy's
nested stencils do not intersect, so an inner stencil silently stops clipping
anything. That bug had the pattern spilling past the page edge onto the
window background.

Text over the pattern measures about 15:1 contrast, well clear of the 4.5:1
floor.

### Fields that may not be there

DG11 and DG12 are optional and plenty of real passports omit them entirely —
place of birth, date of issue and issuing authority are printed on the page but
never written to the chip. Those fields say **"not on chip"** rather than
showing an empty value, so a missing data group is not mistaken for a parse
failure.

The **personal number** is recovered from the MRZ optional-data field when
DG11 is absent — several states, Sweden among them, put the national identity
number there. The field's caption says `PERSONAL No. (FROM MRZ)` when it came
from that fallback.

### What the SECURITY tab does and does not check

It hashes each dumped data group and compares against the hash table inside
EF_SOD, marking every DG **match / MISMATCH / not checked**. It does **not**
validate the signer certificate chain — that needs the issuing country's CSCA
certificate, which the app deliberately does not fetch.

## Where your reads go

Every read writes to:

```
~/.local/share/ePassport/dumps/<UTC-timestamp>/
```

created `0700`. The app was previously called `pm3-passport`; if a directory
of that name exists it is moved to the new one on first run, so earlier reads
are carried across rather than orphaned. You do not need to remember that: **Dumps…** in the toolbar
lists every read with its timestamp and contents. From there you can open one,
delete one with the bin button, open the folder in your file manager, or clear
out the empty directories left behind by reads that failed. The path is also in
the status bar (click it) and in the log at the start of every read.

Every read also leaves `pm3.log` in its directory: the client output for that
run, which is the only record of why a read that dumped nothing gave up. It
holds what the LOG pane showed and not the MRZ or CAN you typed, and it does
not count as a file when the app decides whether a read produced anything.

Deleting always asks first, and says what it is about to destroy — a dump holds
a real portrait and a real MRZ.

**Opening a dump from elsewhere** (a colleague's, or the generated samples):
**Dumps… → Samples…** goes straight to `./samples`, and **Browse…** opens a
picker with one-click jumps to **Recent**, **Dumps**, **Samples**, **Working
dir** and **Home**, plus a path box you can type or paste into.

The picker reopens **beside the last dump you loaded**, so picking a second
dump next to the first does not mean navigating there again. Shortcuts that do
not exist are not shown — `Samples` only appears once you have generated them —
and duplicates collapse, so `Recent` and `Samples` do not both appear when they
are the same folder.

## Your data

- Dumps are `0700` and there is a **Delete dump** button.
- MRZ values and document numbers are never written outside that directory.
- "Remember" on the entry screen defaults to **off** — those values are live
  credential material.
- The app is strictly read-only: it displays what the chip returns, and no
  field is editable.

## Development

```bash
make test              # 297 tests, no hardware needed
make samples           # generate the fabricated dumps into ./samples
make clean             # drop __pycache__ and the test cache
make distclean         # the above, plus the generated samples
make format            # reformat with black
make help              # the rest
```

The proxmark3 root `Makefile` recurses in here too, following the same pattern
it uses for `hitag2crack`:

```bash
make ePassport/clean     # from the repository root
make ePassport/test
make ePassport/help
```

ePassport is deliberately **not** in the root `TARGETS`, so a plain `make` or
`make clean` at the top level does not touch it — it builds nothing and is not
part of the firmware or client build.

`make` shells out to `python3`; if your dependencies live in a virtualenv,
point it at that interpreter:

```bash
make test PYTHON=/path/to/venv/bin/python
```

The same without `make`:

```bash
python3 -m pytest tests/ -q
python3 tools_make_sample.py [DIR]              # generate the sample dumps
python3 -m epassport.emrtd samples/td3_utopia   # headless: parse and print
python3 -m black epassport tests tools_*.py
```

### Nothing derived from a document is checked in

This tree carries **no dumps, no logs and no images**. A dump holds a live
portrait and MRZ, and a screenshot of one is just as identifying — so none of
it belongs in version control, not even the fabricated kind, and `.gitignore`
refuses the file types outright.

What you need instead is generated:

```bash
python3 tools_make_sample.py [DIR]      # fabricated dumps, default ./samples
```

They are documents of the fictional ICAO specimen state "Utopia": no real
personal data, no real security print. `td3_utopia` carries a genuinely signed
EF_SOD, `td3_utopia_tampered` is the same document with DG2 swapped after
signing so the SECURITY tab has a MISMATCH to show, and `td1_utopia_idcard` is
a TD1 card with no DG11/DG12 or SOD.

The tests never touch that directory: `tests/conftest.py` builds its own copy
into a temporary directory, and the recorded pm3 sessions used by the
`--dry-run` tests are inline in `tests/test_pm3_client.py`.

To replay a real session, record it yourself:

```bash
pm3 -c "hf emrtd dump -n ... -d ... -e ..." | tee pm3.log
```

### Layout

```
Makefile             run / test / format / clean
ePassport.py         the launcher; everything below is the implementation
epassport/
  app.py               app, screens, worker threads
  __main__.py          shim so `python3 -m epassport` still works
  config.py            paths, settings, 0700 data dir
  pm3/client.py        subprocess, streaming, cancel, timeout
  pm3/errors.py        typed failures + plain-English remedies
  emrtd/tlv.py         BER-TLV reader
  emrtd/mrz.py         TD1/TD2/TD3, check digits, date window
  emrtd/dg.py          per-DG decoders -> PassportRecord
  emrtd/sod.py         optional CMS/SOD inspection
  emrtd/images.py      JPEG/JP2 carving out of CBEFF blobs
  emrtd/model.py       PassportRecord: the single UI-facing object
  ocr/                 camera thread, OCR pipeline, accept rule
  ui/                  Kivy widgets and .kv files
```

**Threading contract:** the pm3 subprocess, file parsing, image decoding and
OCR all run off the main thread; UI mutation happens only via
`Clock.schedule_once`. The app never freezes while a dump runs.

**Single source of truth:** every parser produces one `PassportRecord`, and the
UI binds only to that — which is why "open saved dump" and "read from card" are
the same rendering path.
