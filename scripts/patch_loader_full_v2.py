#!/usr/bin/env python3
"""
patch_loader_full_v2.py - RouterOS ARM loader patcher (version endurecida)

Reemplazo directo de patch_loader_full.py. Mismos pasos (4 fases) y mismos
artefactos de salida, pero con derivacion automatica y guards que fallan fuerte
en vez de fallar en silencio.

QUE SE ELIMINO (y por que)
--------------------------
1. VERSION_TABLE / VERSION_STRINGS  -> las direcciones internas del payload ya no
   se escriben a mano: se derivan del layout (cadenas consecutivas desde 0x410) y
   de las constantes del propio payload. El nombre del companero (mode / mode2) se
   detecta en el rootfs extraido.
0. DEPENDENCIA DEL LOADER PREBUILT DE ELSEIF -> se elimina. Por defecto (--payload self) el
   payload ARM lo genera este script (288 bytes) y hace lo mismo que el de referencia:
     - hook de la GOT de memcmp -> stub "mov r0,#0 ; bx lr"
     - reparacion de la cabecera ELF EN MEMORIA via /proc/self/mem: restaura el e_entry, el
       e_shnum y el PT_GNU_STACK originales, para que la copia en memoria del loader vuelva a
       parecer la de fabrica (evita que un chequeo de integridad del propio loader falle)
     - salto al _start original con los registros intactos
   NO ejecuta rc.local ni keygen (eso era de elseif y generaria licencias solo). Se verifica
   desensamblando con capstone y, si hay unicorn, EMULANDO las syscalls (open/lseek/write sobre
   /proc/self/mem) para comprobar que la cabecera queda reparada de verdad.
   Con --payload asset se puede seguir usando el payload de un loader de referencia.
0b. PARCHE DEL COMPANERO (keyman / mode / mode2) -> receta deducida de una imagen que funciona
   en hardware y validada byte a byte: keyman se parchea EN SU SITIO, mode tambien y se crea
   mode2 (40 bytes: el marcador r3 = 0x1640CC25 y la clave propia en la disposicion de cada
   fichero). El payload del loader comprueba ese marcador en /proc/self/mem... en /nova/bin/mode2.
   El loader NO lleva la clave propia por defecto: la imagen de referencia conserva la de
   MikroTik y licencia por el hook (usa --embed-keys si quieres lo contrario).
2. Fallback silencioso a 7.24.2     -> si la version no tiene pistas de offsets del
   companero y no se pueden derivar, el script ABORTA (ya no produce un payload con
   direcciones equivocadas sin avisar).
3. Offsets fijos NEW_ENTRY=0x34000 / PAYLOAD_FILE_OFFSET=0x14000 / PAYLOAD_SIZE=0x50C
   -> ahora se derivan del ELF destino:
        payload_file_offset = align_up(fin_de_todo, 0x1000)
        payload_vaddr       = align_up(max(p_vaddr+p_memsz de los PT_LOAD), 0x1000)
        payload_len         = p_filesz del segmento payload del loader de referencia
   (con los loaders reales esto reproduce exactamente 0x14000 / 0x34000 / 0x50C)
4. find_memcmp_got() era codigo muerto -> ahora SI se usa: el slot GOT de memcmp y el
   e_entry original del destino se escriben en el payload (celdas 0x4A0 / 0x4A4), con lo
   que el parche deja de depender del build.
5. Tabla /proc/self/mem fija        -> se genera desde el ELF destino: e_entry, e_shnum y
   el PT_GNU_STACK original (bytes crudos) con sus direcciones virtuales reales.
6. Ruta /root/MikroTikPatch/...     -> se usa PATCHED_LOADER_PATH (la variable que ya
   respeta patch.py) y rutas relativas al directorio del script, no al CWD.
7. python3 literal                  -> sys.executable (PATCH_PYTHON para forzarlo).
8. Carving del SquashFS por "hsqs"  -> se extrae la parte SQUASHFS real via NovaPackage.
9. mksquashfs con opciones fijas    -> se copian las del SquashFS original (xz + BCJ arm,
   bloque de 512K, dict_size y -no-xattrs leidos del superbloque). El .npk de MikroTik usa
   BCJ arm; reempaquetar sin el produce imagenes mas grandes (medido: +808 KB en 7.23.2).
10. BRICK EN 7.24.x POR ROSMODE.MSG -> se anade --mode-arm y --mode-arm-password. El parche
   del companero deja /nova/bin/mode parcheado, pero en 7.24.x ese mode parcheado no crea
   /rw/rosmode.msg al arrancar y el sistema se cuelga. Con --mode-arm, el script sustituye:
     - /nova/bin/mode2 := mode ORIGINAL de la version (sin parchear)
     - /nova/bin/mode  := binario mode_arm (shim que crea rosmode.msg y ejecuta mode2)
   El binario mode_arm se puede pasar como fichero ELF o como ZIP con password (AES via
   pyzipper, ZipCrypto via zipfile). El password se pasa con --mode-arm-password o la
   variable de entorno MODE_ARM_PASSWORD.

GUARDS QUE SE AÑADIERON
-----------------------
* Valida ELF32/LSB/ET_EXEC/EM_ARM, presencia de PT_GNU_STACK y de memcmp en .dynsym.
* Comprueba que la region [payload_file_offset, +len) no pise ninguna seccion, ningun
  segmento ni la tabla de shdr, y que no desborde el archivo de forma destructiva.
* Comprueba que el shdr nuevo quepa en el hueco (e_shoff + (e_shnum+1)*40 <= payload_off).
* Verificacion post-escritura: reparsea el loader generado y revalida cabecera, phdr,
  indice shdr, celdas derivadas y cadenas descifradas (round-trip).
* Verifica el companero (/nova/bin/mode[2]) y avisa CLARAMENTE si el marcador que
  espera el payload no esta: en ese caso el hook de memcmp NO se instala y la
  verificacion de licencia seguiria activa.
* Preflight de modulos (elftools/npk/pefile/mikro) y de las variables de firma que
  necesita patch.py, antes de empezar (no a mitad del pipeline).
* Verificacion end-to-end: extrae el loader del .npk FINAL y lo compara con el generado.
* --check-keys: valida el material de firma (firma + verifica un .npk minimo) antes de
  arrancar el pipeline y comprueba que las claves propias difieren de las oficiales.
  Ojo: mikro.py necesita ademas 'sha256' (sha256.py) y 'toyecc' (carpeta toyecc/), los
  dos del mismo repo upstream; el preflight lo comprueba.
* --companion-markers / --markers-from-patchpy / --companion-name: el payload verifica unos
  bytes concretos en /nova/bin/mode[2] y solo entonces instala el hook de memcmp. Si esos bytes
  no coinciden con lo que escribe la herramienta que parchea el companero, el bypass no se
  activa. Con --markers-from-patchpy se derivan de patch.py eligiendo la variante que de verdad
  se aplicara al fichero real (comprobando su patron old_codes), y --companion-name permite
  apuntar a la copia que esa herramienta escribe realmente (p.ej. mode_, porque patch.py
  upstream parchea "mode_" y no "mode").
* --self-test: suite offline que demuestra la derivacion contra los loaders reales.
* Descargas: no se usa wget (era la v1). Por defecto se descarga por tramos HTTP en paralelo
  (8 conexiones, con If-Range sobre el ETag y reintento por tramo) y, si aria2c esta en PATH
  o se pasa --downloader aria2, se usa aria2c con esas mismas conexiones.

Uso:
    python3 patch_loader_full_v2.py <version> <arch> [opciones]
    python3 patch_loader_full_v2.py --self-test

Ejemplos:
    python3 patch_loader_full_v2.py 7.24.2 arm --reference-loader loader_parcheado
    python3 patch_loader_full_v2.py 7.23.2 arm --npk routeros-7.23.2-arm.npk --loader-only
    python3 patch_loader_full_v2.py 7.24.4 arm --npk routeros-7.24.4-arm.npk \
        --keys-file CLAVES.txt --mode-arm mode_arm.zip --skip-all-packages --skip-netinstall
    python3 patch_loader_full_v2.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = os.environ.get("PATCH_PYTHON") or sys.executable or "python3"
NPK_PY = Path(os.environ.get("NPK_PY") or (HERE / "npk.py"))
PATCH_PY = Path(os.environ.get("PATCH_PY") or (HERE / "patch.py"))

MACHINE_ARM = 40
PAGE = 0x1000

USER_AGENT = "patch_loader_full_v2"
DOWNLOAD_THREADS = 8
DOWNLOADER = "auto"
FORCE_DOWNLOAD = False
MIN_PARALLEL_SIZE = 1 << 20
CHUNK_TIMEOUT = 30
CHUNK_ATTEMPTS = 4

CODE_END = 0x3B8
CELL_ARGV = 0x3B8
CELL_SLOTS = 0x3BC
CELL_EXTRA = 0x3D8
ARGV_OFF = 0x3F0
STRINGS_OFF = 0x410
STRINGS_LIMIT = 0x4A0
GOT_CELL = 0x4A0
ENTRY_CELL = 0x4A4
TABLEPTR_CELL = 0x4A8
MEMTAB_OFF = 0x4B0
COPYTAB_OFF = 0x4EC
STUB_OFF = 0x250
PAYLOAD_LEN = 0x50C
COPY_RECORD_LEN = 9

SLOT_BASH, SLOT_KEYGEN, SLOT_RCLOCAL, SLOT_STARTMSG, SLOT_ENTRYCELL, SLOT_COMPANION, SLOT_TABLEPTR = range(7)

STR_BASH = b"/pckg/option/bin/bash"
STR_RCLOCAL = b"/rw/disk/rc.local"
STR_KEYGEN = b"/pckg/option/bin/keygen"
STR_STARTMSG = b"Starting rc.local...\n"
STR_CONSOLE = b"/dev/console"
STR_MEM = b"/proc/self/mem"
COMPANION_KEYS = ("bash", "rc", "companion", "keygen", "start", "console", "mem")
COMPANION_CANDIDATES = ("mode2", "mode")

COMPANION_COPY_HINTS = {
    "7.22.2": [0x0000DF60, 0x0000DF64, 0x0000DF68],
    "7.23.2": [0x0000DF60, 0x0000DF64, 0x0000DF68],
    "7.24.2": [0x0000E974, 0x0000E978, 0x0000E97C],
}

ENV_KEYS_REQUIRED = (
    "MIKRO_LICENSE_PUBLIC_KEY",
    "MIKRO_NPK_SIGN_PUBLIC_KEY",
    "CUSTOM_LICENSE_PUBLIC_KEY",
    "CUSTOM_NPK_SIGN_PUBLIC_KEY",
    "CUSTOM_LICENSE_PRIVATE_KEY",
    "CUSTOM_NPK_SIGN_PRIVATE_KEY",
)

SIGNING_MODULES = ("mikro", "sha256", "toyecc")

URL_ENV_VARS = (
    "MIKRO_LICENCE_URL", "CUSTOM_LICENCE_URL", "MIKRO_RENEW_URL", "CUSTOM_RENEW_URL",
    "MIKRO_UPGRADE_URL", "CUSTOM_UPGRADE_URL", "MIKRO_CLOUD_URL", "CUSTOM_CLOUD_URL",
    "MIKRO_CLOUD2_URL", "CUSTOM_CLOUD2_URL", "MIKRO_CLOUD_PUBLIC_KEY", "CUSTOM_CLOUD_PUBLIC_KEY",
)

STOCK_SIZES_FILE = "stock_sizes.json"

URL_PAIRS = (
    ("MIKRO_LICENCE_URL", "CUSTOM_LICENCE_URL"),
    ("MIKRO_RENEW_URL", "CUSTOM_RENEW_URL"),
    ("MIKRO_UPGRADE_URL", "CUSTOM_UPGRADE_URL"),
    ("MIKRO_CLOUD_URL", "CUSTOM_CLOUD_URL"),
    ("MIKRO_CLOUD2_URL", "CUSTOM_CLOUD2_URL"),
    ("MIKRO_CLOUD_PUBLIC_KEY", "CUSTOM_CLOUD_PUBLIC_KEY"),
)


def check_elf_integrity(rootfs_dir: Path) -> "list[tuple[str, str]]":
    malos: "list[tuple[str, str]]" = []
    for p in sorted(rootfs_dir.rglob("*")):
        if not p.is_file():
            continue
        try:
            d = p.read_bytes()
        except OSError:
            continue
        if len(d) < 0x40 or d[:4] != b"\x7fELF":
            continue
        e_shoff = struct.unpack_from("<I", d, 0x20)[0]
        e_shentsize = struct.unpack_from("<H", d, 0x2E)[0]
        e_shnum = struct.unpack_from("<H", d, 0x30)[0]
        rel = str(p.relative_to(rootfs_dir))
        if e_shoff + e_shnum * e_shentsize > len(d):
            malos.append((rel, "la tabla de secciones se sale del fichero"))
            continue
        for i in range(e_shnum):
            base = e_shoff + i * e_shentsize
            sh_type = struct.unpack_from("<I", d, base + 4)[0]
            sh_offset = struct.unpack_from("<I", d, base + 0x10)[0]
            sh_size = struct.unpack_from("<I", d, base + 0x14)[0]
            sh_link = struct.unpack_from("<I", d, base + 0x18)[0]
            if sh_type == 0 or sh_size == 0 or sh_type == 8:
                continue
            if sh_offset + sh_size > len(d):
                malos.append((rel, f"la seccion {i} (tipo {sh_type}) se sale del fichero"))
                break
            if sh_type == 11 and sh_link < e_shnum:
                lb = e_shoff + sh_link * e_shentsize
                lo = struct.unpack_from("<I", d, lb + 0x10)[0]
                ls = struct.unpack_from("<I", d, lb + 0x14)[0]
                if lo + ls > len(d) or (ls and d[lo] != 0):
                    malos.append((rel, "la tabla de cadenas dinamica (.dynstr) no es valida"))
                    break
    return malos


def rootfs_size_manifest(rootfs_dir: Path) -> "dict[str, int]":
    manifest: "dict[str, int]" = {}
    for p in sorted(rootfs_dir.rglob("*")):
        try:
            if p.is_file():
                manifest[str(p.relative_to(rootfs_dir))] = p.stat().st_size
        except OSError:
            continue
    return manifest


def check_size_manifest(
    manifest: "dict[str, int]",
    rootfs_dir: Path,
    allowed: "tuple[str, ...]" = ("loader", "logo.txt"),
) -> "tuple[list[tuple[str, int, int]], list[tuple[str, int, int]]]":
    elf: "list[tuple[str, int, int]]" = []
    otros: "list[tuple[str, int, int]]" = []
    for rel, tam in manifest.items():
        if Path(rel).name in allowed:
            continue
        p = rootfs_dir / rel
        try:
            if not p.exists():
                elf.append((rel, tam, -1))
                continue
            ahora = p.stat().st_size
            if ahora == tam:
                continue
            cabecera = b""
            if ahora >= 4:
                with p.open("rb") as fh:
                    cabecera = fh.read(4)
        except OSError:
            continue
        (elf if cabecera == b"\x7fELF" else otros).append((rel, tam, ahora))
    return elf, otros


def discard_bad_output(npk_path: Path, mensaje: str) -> None:
    try:
        npk_path.unlink()
        warn(f"borrado el .npk defectuoso: {npk_path}")
    except OSError:
        pass
    fail(mensaje)


def filter_url_env(env: "dict[str, str]") -> None:
    for viejo, nuevo in URL_PAIRS:
        a, b = env.get(viejo, ""), env.get(nuevo, "")
        if a and b and len(a) != len(b):
            warn(
                f"URL {viejo} -> {nuevo}: longitudes distintas ({len(a)} -> {len(b)}); se omite "
                "para no desplazar los binarios de patch.py"
            )
            env.pop(viejo, None)
            env.pop(nuevo, None)


def patch_py_env(args, **extra: str) -> "dict[str, str]":
    env = dict(os.environ)
    env["ARCH"] = args.arch.replace("-", "")
    env.update(extra)
    if not args.url_rewrite:
        for var in URL_ENV_VARS:
            env.pop(var, None)
    else:
        filter_url_env(env)
    return env


# ==========================================================================
#  utilidades
# ==========================================================================
class PatchError(RuntimeError):
    pass


def log(msg: str = "") -> None:
    print(msg, flush=True)


def ok(msg: str) -> None:
    print(f"[OK]   {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"[WARN] {msg}", flush=True)


def info(msg: str) -> None:
    print(f"[+]    {msg}", flush=True)


def fail(msg: str) -> "None":
    raise PatchError(msg)


def align_up(value: int, align: int) -> int:
    return (value + align - 1) & ~(align - 1)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256(Path(path).read_bytes())


def which(tool: str) -> "str | None":
    return shutil.which(tool)


def require_tools(*tools: str) -> None:
    missing = [t for t in tools if which(t) is None]
    if missing:
        fail(
            "faltan herramientas en PATH: "
            + ", ".join(missing)
            + " (son de Linux: ejecuta el script en Linux/WSL; --self-test, --check-keys y "
            "--loader-only con --original-loader si funcionan sin ellas)"
        )


def have_module(name: str) -> bool:
    try:
        import importlib.util
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


def require_modules(*names: str) -> None:
    missing = [n for n in names if not have_module(n)]
    if missing:
        fail(
            "faltan modulos Python: "
            + ", ".join(missing)
            + " (pip install pyelftools; mikro/pefile deben venir del repo MikroTikPatch)"
        )


def run(cmd: "list[str]", desc: str, env: "dict[str, str] | None" = None) -> None:
    printable = " ".join(str(c) for c in cmd)
    info(desc or printable)
    proc = subprocess.run(cmd, env=env)
    if proc.returncode != 0:
        fail(f"fallo el comando ({proc.returncode}): {printable}")


def obfuscate_string(s: bytes) -> bytes:
    out = bytearray()
    for i, c in enumerate(s):
        out.append(((c ^ (0xA9 ^ i)) + 1) & 0xFF)
    out.append(0)
    return bytes(out)


def deobfuscate_string(blob: bytes, off: int) -> bytes:
    out = bytearray()
    i = 0
    while off + i < len(blob) and blob[off + i] != 0:
        out.append(((blob[off + i] - 1) & 0xFF) ^ ((0xA9 ^ i) & 0xFF))
        i += 1
    return bytes(out)


def pack_u32(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<I", buf, off, value & 0xFFFFFFFF)


# ==========================================================================
#  ZIP con password (para --mode-arm)
# ==========================================================================
def _is_zip_file(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"PK\x03\x04"
    except OSError:
        return False


def _extract_mode_arm_from_zip(zip_path: Path, password: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    pwd_bytes = password.encode() if isinstance(password, str) else password

    def _pick_and_extract(names, open_fn):
        candidates = [n for n in names
                      if Path(n).name in ("mode_arm", "mode_arm.elf", "mode_arm.bin")]
        if candidates:
            with open_fn(candidates[0]) as src:
                data = src.read()
            out_path = out_dir / "mode_arm"
            out_path.write_bytes(data)
            return out_path
        return None

    # Intento 1: pyzipper (AES + ZipCrypto, mas completo)
    try:
        import pyzipper
        with pyzipper.AESZipFile(zip_path, "r") as zf:
            zf.pwd = pwd_bytes
            result = _pick_and_extract(zf.namelist(), zf.open)
            if result:
                return result
            zf.extractall(out_dir)
            hits = sorted(out_dir.rglob("mode_arm*"))
            if hits:
                return hits[0]
            fail(f"no se encontro 'mode_arm' dentro de {zip_path}")
    except ImportError:
        pass
    except Exception as exc:
        fail(f"pyzipper fallo con {zip_path}: {exc}")

    # Intento 2: zipfile (ZipCrypto legacy)
    try:
        with zipfile.ZipFile(zip_path) as zf:
            zf.setpassword(pwd_bytes)
            result = _pick_and_extract(zf.namelist(),
                                       lambda n: zf.open(n, pwd=pwd_bytes))
            if result:
                return result
            zf.extractall(out_dir, pwd=pwd_bytes)
            hits = sorted(out_dir.rglob("mode_arm*"))
            if hits:
                return hits[0]
            fail(f"no se encontro 'mode_arm' dentro de {zip_path}")
    except RuntimeError as exc:
        fail(f"password incorrecto para {zip_path}: {exc}")
    except Exception as exc:
        fail(f"zipfile fallo con {zip_path}: {exc}")


def _resolve_mode_arm(path_arg: str, password: "str | None", out_dir: Path) -> Path:
    path = Path(path_arg)
    if not path.exists():
        fail(f"--mode-arm no existe: {path.resolve()}")
    if _is_zip_file(path):
        if not password:
            fail(
                f"{path.name} es un ZIP con password: pasa --mode-arm-password o "
                "exporta MODE_ARM_PASSWORD"
            )
        info(f"extrayendo mode_arm de {path.name}...")
        return _extract_mode_arm_from_zip(path, password, out_dir)
    return path


# ==========================================================================
#  modelo ELF + derivacion
# ==========================================================================
@dataclass
class Phdr:
    index: int
    p_type: int
    p_offset: int
    p_vaddr: int
    p_paddr: int
    p_filesz: int
    p_memsz: int
    p_flags: int
    p_align: int
    raw: bytes

    @property
    def type_name(self) -> str:
        return {
            1: "PT_LOAD", 2: "PT_DYNAMIC", 3: "PT_INTERP", 4: "PT_NOTE", 6: "PT_PHDR",
            0x6474E551: "PT_GNU_STACK", 0x6474E552: "PT_GNU_RELRO", 0x70000001: "PT_ARM_EXIDX",
        }.get(self.p_type, f"0x{self.p_type:08X}")

    @property
    def vaddr_end(self) -> int:
        return self.p_vaddr + self.p_memsz


@dataclass
class ElfModel:
    label: str
    size: int
    entry: int
    phoff: int
    shoff: int
    phentsize: int
    phnum: int
    shentsize: int
    shnum: int
    phdrs: "list[Phdr]"
    section_ranges: "list[tuple[str, int, int, int]]"
    memcmp_got: "int | None"

    header_delta: int = 0
    used_end: int = 0
    payload_file_offset: int = 0
    payload_vaddr: int = 0
    gnu_stack_idx: "int | None" = None
    gnu_stack_raw: bytes = b""
    max_load_vaddr_end: int = 0

    @property
    def shdr_end(self) -> int:
        return self.shoff + self.shnum * self.shentsize

    @staticmethod
    def from_bytes(data: bytes, label: str = "<mem>") -> "ElfModel":
        if len(data) < 0x34:
            fail(f"{label}: archivo demasiado pequeno para ser ELF")
        if data[:4] != b"\x7fELF":
            fail(f"{label}: no es un ELF")
        if data[4] != 1:
            fail(f"{label}: se esperaba ELF32 (EI_CLASS={data[4]})")
        if data[5] != 1:
            fail(f"{label}: se esperaba little-endian (EI_DATA={data[5]})")
        e_type, e_machine = struct.unpack_from("<HH", data, 0x10)
        if e_type != 2:
            fail(f"{label}: se esperaba ET_EXEC (e_type={e_type})")
        if e_machine != MACHINE_ARM:
            fail(f"{label}: se esperaba EM_ARM (e_machine={e_machine})")

        entry = struct.unpack_from("<I", data, 0x18)[0]
        phoff = struct.unpack_from("<I", data, 0x1C)[0]
        shoff = struct.unpack_from("<I", data, 0x20)[0]
        phentsize = struct.unpack_from("<H", data, 0x2A)[0]
        phnum = struct.unpack_from("<H", data, 0x2C)[0]
        shentsize = struct.unpack_from("<H", data, 0x2E)[0]
        shnum = struct.unpack_from("<H", data, 0x30)[0]

        phdrs: "list[Phdr]" = []
        for i in range(phnum):
            off = phoff + i * phentsize
            raw = data[off:off + 32]
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
                struct.unpack("<IIIIIIII", raw)
            phdrs.append(
                Phdr(i, p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align, raw)
            )

        sections: "list[tuple[str, int, int, int]]" = []
        if shoff and shnum and shentsize:
            strtab_off = 0
            if shnum > 0:
                strtab_idx = struct.unpack_from("<H", data, 0x32)[0]
                if strtab_idx < shnum:
                    strtab_off = struct.unpack_from("<I", data,
                                                    shoff + strtab_idx * shentsize + 0x10)[0]
            for i in range(shnum):
                base = shoff + i * shentsize
                if base + 40 > len(data):
                    break
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = \
                    struct.unpack_from("<IIIIII", data, base)
                name = ""
                if strtab_off and sh_name:
                    end = data.find(b"\x00", strtab_off + sh_name)
                    name = data[strtab_off + sh_name: end if end > 0 else None].decode("latin1")
                sections.append((name, sh_offset, sh_size, sh_flags))

        model = ElfModel(
            label=label, size=len(data), entry=entry, phoff=phoff, shoff=shoff,
            phentsize=phentsize, phnum=phnum, shentsize=shentsize, shnum=shnum,
            phdrs=phdrs, section_ranges=sections,
            memcmp_got=find_memcmp_got(data, label),
        )
        model._derive()
        return model

    @staticmethod
    def from_file(path: Path) -> "ElfModel":
        path = Path(path)
        if not path.exists():
            fail(f"no existe: {path}")
        return ElfModel.from_bytes(path.read_bytes(), str(path))

    def _derive(self) -> None:
        header_loads = [p for p in self.phdrs if p.p_type == 1 and p.p_offset == 0]
        if not header_loads:
            fail(f"{self.label}: no hay PT_LOAD que mapee la cabecera (offset 0)")
        self.header_delta = header_loads[0].p_vaddr - header_loads[0].p_offset

        loads = [p for p in self.phdrs if p.p_type == 1]
        self.max_load_vaddr_end = max((p.vaddr_end for p in loads), default=0)

        ends = [self.size, self.shdr_end]
        for name, off, size, flags in self.section_ranges:
            if size:
                ends.append(off + size)
        for p in self.phdrs:
            if p.p_type == 1 and p.p_filesz:
                ends.append(p.p_offset + p.p_filesz)
        self.used_end = max(ends)

        self.payload_file_offset = align_up(self.used_end, PAGE)
        self.payload_vaddr = align_up(self.max_load_vaddr_end, PAGE) if self.max_load_vaddr_end else 0

        for p in self.phdrs:
            if p.p_type == 0x6474E551:
                self.gnu_stack_idx = p.index
                self.gnu_stack_raw = p.raw
                break

    def guards(self, payload_len: int, shdr_grow: int) -> "list[str]":
        warnings: "list[str]" = []
        start, end = self.payload_file_offset, self.payload_file_offset + payload_len

        if self.payload_vaddr == 0:
            fail(f"{self.label}: no se pudo derivar la vaddr del payload")
        if self.payload_vaddr % PAGE:
            fail(f"{self.label}: vaddr derivada no alineada a pagina")

        for p in self.phdrs:
            if p.p_type != 1:
                continue
            if p.p_filesz and not (end <= p.p_offset or start >= p.p_offset + p.p_filesz):
                fail(f"{self.label}: la region del payload solapa {p.type_name}[{p.index}]")
            if p.p_memsz and not (self.payload_vaddr + payload_len <= p.p_vaddr or
                                  self.payload_vaddr >= p.vaddr_end):
                fail(f"{self.label}: la vaddr del payload solapa {p.type_name}[{p.index}]")

        for name, off, size, flags in self.section_ranges:
            if not size:
                continue
            if not (end <= off or start >= off + size):
                fail(f"{self.label}: la region del payload solapa la seccion "
                     f"{name or '<sin nombre>'}")

        need = self.shoff + (self.shnum + shdr_grow) * self.shentsize
        if need > start:
            fail(f"{self.label}: el shdr nuevo no cabe (terminaria en 0x{need:X})")

        if self.gnu_stack_idx is None:
            fail(f"{self.label}: no se encontro PT_GNU_STACK")
        if self.memcmp_got is None:
            fail(f"{self.label}: no se encontro la GOT de memcmp")

        warnings.append(
            "el parche reemplaza PT_GNU_STACK por un PT_LOAD RWX: la pila del proceso "
            "queda ejecutable (es el comportamiento del parche original)"
        )
        if self.size > self.payload_file_offset:
            fail(f"{self.label}: coherencia interna (size > payload_file_offset)")
        return warnings


def find_memcmp_got(data: bytes, label: str = "<mem>") -> "int | None":
    try:
        from elftools.elf.elffile import ELFFile
    except Exception:
        return None
    import io
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection

    elf = ELFFile(io.BytesIO(data))
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None:
        return None
    sym_idx = None
    for i, sym in enumerate(dynsym.iter_symbols()):
        if sym.name == "memcmp":
            sym_idx = i
            break
    if sym_idx is None:
        return None
    for section in elf.iter_sections():
        if isinstance(section, RelocationSection):
            for rel in section.iter_relocations():
                if rel["r_info_sym"] == sym_idx:
                    return int(rel["r_offset"])
    return None


# ==========================================================================
#  PAYLOAD PROPIO
# ==========================================================================
SELF_STUB_BYTES = b"\x00\x00\xa0\xe3" + b"\x1e\xff\x2f\xe1"
SELF_MEM_PATH = b"/proc/self/mem\x00"


class _ArmBuilder:
    def __init__(self) -> None:
        self.words: "list[int]" = []
        self.ldr_fix: "list[tuple[int, str, int]]" = []
        self.bl_fix: "list[tuple[int, str, int]]" = []
        self.labels: "dict[str, int]" = {}
        self.literals: "dict[str, int]" = {}
        self.data = bytearray()

    def emit(self, word: int) -> None:
        self.words.append(word & 0xFFFFFFFF)

    def mov_imm(self, rd: int, imm: int) -> None:
        if not 0 <= imm < 256:
            raise AssertionError(f"mov inmediato fuera de rango: {imm}")
        self.emit(0xE3A00000 | (rd << 12) | imm)

    def ldr_lit(self, rd: int, name: str) -> None:
        self.ldr_fix.append((len(self.words), name, rd))
        self.emit(0)

    def bl(self, label: str, cond: int = 0xE) -> None:
        self.bl_fix.append((len(self.words), label, cond))
        self.emit(0)

    def label(self, name: str) -> None:
        self.labels[name] = len(self.words) * 4

    def add_data(self, datos: bytes) -> int:
        while len(self.data) % 4:
            self.data.append(0)
        off = len(self.data)
        self.data += datos
        return off

    def build(self) -> "tuple[bytes, dict]":
        nombres = list(dict.fromkeys(n for _, n, _ in self.ldr_fix))
        slots = {n: len(self.words) * 4 + 4 * i for i, n in enumerate(nombres)}
        for idx, name, rd in self.ldr_fix:
            imm = slots[name] - (idx * 4 + 8)
            if not 0 <= imm < 4096:
                raise AssertionError(f"literal fuera de alcance ({name}): {imm}")
            self.words[idx] = 0xE59F0000 | (rd << 12) | imm
        for idx, label, cond in self.bl_fix:
            delta = self.labels[label] - (idx * 4 + 8)
            if delta % 4:
                raise AssertionError("salto no alineado")
            self.words[idx] = (cond << 28) | 0x0A000000 | ((delta >> 2) & 0xFFFFFF)
        blob = b"".join(struct.pack("<I", w) for w in self.words)
        blob += b"".join(struct.pack("<I", self.literals.get(n, 0)) for n in nombres)
        blob += bytes(self.data)
        return blob, slots


def encode_self_payload(base: int, got_addr: int, entry: int,
                        records: "list[tuple[int, bytes]]") -> "tuple[bytes, int]":
    b = _ArmBuilder()
    b.emit(0xE92D503F)
    b.ldr_lit(0, "got")
    b.ldr_lit(1, "stub")
    b.emit(0xE5801000)
    b.ldr_lit(0, "mem")
    b.mov_imm(1, 1)
    b.mov_imm(2, 0)
    b.mov_imm(7, 5)
    b.emit(0xEF000000)
    b.emit(0xE1A04000)
    b.bl("fin", cond=0xB)

    for i, (vaddr, datos) in enumerate(records):
        b.emit(0xE1A00004)
        b.ldr_lit(1, f"r{i}_vaddr")
        b.mov_imm(2, 0)
        b.mov_imm(7, 19)
        b.emit(0xEF000000)
        b.emit(0xE1A00004)
        b.ldr_lit(1, f"r{i}_data")
        b.mov_imm(2, len(datos))
        b.mov_imm(7, 4)
        b.emit(0xEF000000)

    b.emit(0xE1A00004)
    b.mov_imm(7, 6)
    b.emit(0xEF000000)
    b.label("fin")
    b.emit(0xE8BD503F)
    b.ldr_lit(15, "entry")
    b.label("stub")
    stub_off = len(b.words) * 4
    b.emit(0xE3A00000)
    b.emit(0xE12FFF1E)

    nombres = list(dict.fromkeys(n for _, n, _ in b.ldr_fix))
    data_base = len(b.words) * 4 + 4 * len(nombres)
    mem_rel = b.add_data(SELF_MEM_PATH)
    valores = {
        "got": got_addr,
        "stub": base + stub_off,
        "entry": entry,
        "mem": base + data_base + mem_rel,
    }
    for i, (vaddr, datos) in enumerate(records):
        rel = b.add_data(datos)
        valores[f"r{i}_vaddr"] = vaddr
        valores[f"r{i}_data"] = base + data_base + rel
    b.literals.update(valores)
    blob, _ = b.build()
    return blob, stub_off


def verify_self_payload(plan: "PatchPlan", problems: "list[str]") -> None:
    blob = plan.payload
    stub_off = plan.self_stub_off
    if not 0 < stub_off < len(blob) - 8:
        problems.append(f"offset del stub de memcmp invalido: 0x{stub_off:X}")
        return
    if blob[stub_off:stub_off + 8] != SELF_STUB_BYTES:
        problems.append("el stub de memcmp no es 'mov r0,#0 ; bx lr'")
    for etiqueta, valor in (("GOT de memcmp", plan.memcmp_got), ("stub", plan.vaddr + stub_off),
                            ("_start", plan.stock_entry)):
        if struct.pack("<I", valor) not in blob:
            problems.append(f"el payload no contiene el literal esperado ({etiqueta} = 0x{valor:X})")
    for i, (vaddr, datos) in enumerate(plan.self_records):
        if struct.pack("<I", vaddr) not in blob:
            problems.append(f"falta el literal del registro {i} (0x{vaddr:X})")
        if datos not in blob:
            problems.append(f"faltan los datos del registro {i} ({len(datos)} bytes)")
    if SELF_MEM_PATH not in blob:
        problems.append("el payload no lleva la ruta /proc/self/mem")
    try:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_ARM,
                         capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN)
        insns = list(md.disasm(blob[:stub_off], plan.vaddr))
        if not insns or insns[0].mnemonic != "push":
            problems.append("el payload no empieza con push")
        if sum(1 for i in insns if i.mnemonic == "svc") < 4:
            problems.append("faltan llamadas svc (open/lseek/write)")
        if [i.mnemonic for i in insns][-2:] != ["pop", "ldr"]:
            problems.append("el payload no termina restaurando el estado y saltando al _start")
    except ImportError:
        warn("capstone no disponible: no se desensambla el payload (comprobacion adicional de "
             "seguridad). Instalalo con: pip install capstone")


def emulate_self_payload(patched: bytes, original: ElfModel, plan: "PatchPlan") -> "bool | None":
    try:
        from unicorn import UC_ARCH_ARM, UC_HOOK_INTR, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN, UC_PROT_ALL, Uc
        from unicorn.arm_const import (
            UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
            UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R7, UC_ARM_REG_R12,
            UC_ARM_REG_SP,
        )
    except Exception:
        return None

    model = ElfModel.from_bytes(patched, "<emulacion>")
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)
    for p in model.phdrs:
        if p.p_type != 1:
            continue
        start = p.p_vaddr & ~(PAGE - 1)
        size = ((p.p_vaddr + p.p_memsz) - start + PAGE - 1) & ~(PAGE - 1)
        mu.mem_map(start, size, UC_PROT_ALL)
        if p.p_filesz:
            mu.mem_write(p.p_vaddr, patched[p.p_offset:p.p_offset + p.p_filesz])

    stack = 0x70000000
    mu.mem_map(stack, 0x20000, UC_PROT_ALL)
    sp = stack + 0x10000
    mu.mem_write(sp, struct.pack("<I", 2) + b"\x00" * 12)
    sentinels = {
        UC_ARM_REG_R0: 0xAAAA0000, UC_ARM_REG_R1: 0xBBBB0000, UC_ARM_REG_R2: 0xCCCC0000,
        UC_ARM_REG_R3: 0xDDDD0000, UC_ARM_REG_R4: 0x12340000, UC_ARM_REG_R5: 0x56780000,
        UC_ARM_REG_R12: 0xEEEE0000, UC_ARM_REG_LR: 0x99990000, UC_ARM_REG_SP: sp,
    }
    for reg, value in sentinels.items():
        mu.reg_write(reg, value)

    estado = {"fd": 3, "offset": 0, "visto": []}

    def _syscall(uc, intno, _ud):
        pc = uc.reg_read(UC_ARM_REG_PC)
        previa = struct.unpack("<I", uc.mem_read(pc - 4, 4))[0]
        if previa != 0xEF000000:
            uc.reg_write(UC_ARM_REG_PC, pc + 4)
        num = uc.reg_read(UC_ARM_REG_R7)
        r0, r1, r2 = (uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
        if num == 5:
            ruta = bytes(uc.mem_read(r0, 15)).split(b"\x00")[0]
            estado["visto"].append(f"open({ruta.decode(errors='replace')})")
            uc.reg_write(UC_ARM_REG_R0, estado["fd"] if ruta == b"/proc/self/mem" else -1)
        elif num == 19:
            estado["offset"] = r1
            estado["visto"].append(f"lseek(0x{r1:X})")
            uc.reg_write(UC_ARM_REG_R0, r1)
        elif num == 4:
            datos = bytes(uc.mem_read(r1, r2))
            uc.mem_write(estado["offset"], datos)
            estado["visto"].append(f"write(0x{estado['offset']:X},{r2})")
            uc.reg_write(UC_ARM_REG_R0, r2)
        elif num == 6:
            estado["visto"].append("close")
            uc.reg_write(UC_ARM_REG_R0, 0)
        else:
            uc.reg_write(UC_ARM_REG_R0, -1)

    mu.hook_add(UC_HOOK_INTR, _syscall)

    try:
        mu.emu_start(model.entry, original.entry, count=200)
    except Exception as exc:
        warn(f"la emulacion fallo: {exc}")
        return False

    got = struct.unpack("<I", mu.mem_read(plan.memcmp_got, 4))[0]
    expected = plan.vaddr + plan.self_stub_off
    ok_got = got == expected
    ok_regs = all(mu.reg_read(reg) == value for reg, value in sentinels.items())
    ok_pc = mu.reg_read(UC_ARM_REG_PC) == original.entry
    ok_reparacion = True
    for vaddr, datos in plan.self_records:
        if bytes(mu.mem_read(vaddr, len(datos))) != datos:
            ok_reparacion = False
    log(
        f"   emulacion: GOT 0x{plan.memcmp_got:X} -> 0x{got:X} (esperado 0x{expected:X})"
        f" | cabecera reparada en memoria: {'si' if ok_reparacion else 'NO'}"
        f" | registros {'ok' if ok_regs else 'MAL'}"
        f" | PC final 0x{mu.reg_read(UC_ARM_REG_PC):X} (esperado 0x{original.entry:X})"
    )
    if estado["visto"]:
        log("   syscalls simuladas: " + " ".join(estado["visto"]))
    return ok_got and ok_regs and ok_pc and ok_reparacion


def plan_self_patch(model: ElfModel) -> "PatchPlan":
    records = [
        (model.header_delta + 0x18, struct.pack("<I", model.entry)),
        (model.header_delta + 0x30, struct.pack("<H", model.shnum)),
        (model.header_delta + model.phoff + 32 * model.gnu_stack_idx, model.gnu_stack_raw),
    ]
    payload, stub_off = encode_self_payload(model.payload_vaddr, model.memcmp_got,
                                            model.entry, records)
    warnings = model.guards(len(payload), shdr_grow=1)
    return PatchPlan(
        payload=payload,
        file_offset=model.payload_file_offset,
        vaddr=model.payload_vaddr,
        phdr_index=model.gnu_stack_idx,
        stock_entry=model.entry,
        stock_shnum=model.shnum,
        header_delta=model.header_delta,
        memcmp_got=model.memcmp_got,
        companion_name="",
        copy_offsets=[],
        markers=[],
        stock_gnu_stack_count=sum(1 for p in model.phdrs if p.p_type == 0x6474E551),
        warnings=warnings,
        kind="self",
        self_stub_off=stub_off,
        self_records=records,
    )


# ==========================================================================
#  asset del payload
# ==========================================================================
@dataclass
class PayloadAsset:
    blob: bytes
    base: int
    file_offset: int
    source: str

    @property
    def length(self) -> int:
        return len(self.blob)

    def copy_markers(self) -> "list[bytes]":
        return [
            self.blob[COPYTAB_OFF + i * COPY_RECORD_LEN + 5: COPYTAB_OFF + i * COPY_RECORD_LEN + 9]
            for i in range(3)
        ]

    def strings(self) -> "list[bytes]":
        out: "list[bytes]" = []
        off = STRINGS_OFF
        while off < STRINGS_LIMIT and self.blob[off] != 0:
            s = deobfuscate_string(self.blob, off)
            out.append(s)
            off += len(s) + 1
        return out

    def companion_name(self) -> "str | None":
        for name in COMPANION_CANDIDATES:
            if f"/nova/bin/{name}".encode() in self.strings():
                return name
        return None


def load_asset(path: Path) -> PayloadAsset:
    data = Path(path).read_bytes()
    model = ElfModel.from_bytes(data, str(path))

    cands = [p for p in model.phdrs if p.p_type == 1 and p.p_vaddr == model.entry and p.p_filesz]
    if not cands:
        fail(f"{path}: no parece un loader ya parcheado")
    seg = cands[0]
    blob = data[seg.p_offset: seg.p_offset + seg.p_filesz]

    if len(blob) < COPYTAB_OFF + 32:
        fail(f"{path}: payload demasiado pequeno (0x{len(blob):X} bytes)")
    if len(blob) != COPYTAB_OFF + 32:
        fail(f"{path}: payload de 0x{len(blob):X} bytes; el layout conocido termina en "
             f"0x{COPYTAB_OFF + 32:X}")
    if len(blob) != PAYLOAD_LEN:
        fail(f"{path}: payload de 0x{len(blob):X} bytes, se esperaba 0x{PAYLOAD_LEN:X}")

    asset = PayloadAsset(blob=blob, base=seg.p_vaddr, file_offset=seg.p_offset, source=str(path))

    strings = asset.strings()
    if not strings or not strings[0].startswith(b"/"):
        fail(f"{path}: las cadenas del payload no se descifran")
    if asset.companion_name() is None:
        fail(f"{path}: el payload no referencia /nova/bin/{'/'.join(COMPANION_CANDIDATES)}")
    if asset.blob[CELL_ARGV: CELL_ARGV + 4] != struct.pack("<I", asset.base + ARGV_OFF):
        warn(f"{path}: CELL_ARGV inesperado en el asset (se regenerara igualmente)")
    return asset


# ==========================================================================
#  generacion del payload
# ==========================================================================
def build_payload(
    asset: PayloadAsset,
    *,
    base: int,
    companion_name: str,
    memcmp_got: int,
    stock_entry: int,
    stock_shnum: int,
    phoff: int,
    gnu_stack_idx: int,
    gnu_stack_raw: bytes,
    copy_offsets: "list[int]",
    header_delta: int,
    markers: "list[bytes] | None" = None,
) -> bytes:
    if gnu_stack_idx is None:
        fail("no se puede generar el payload: el destino no tiene PT_GNU_STACK")
    if not memcmp_got:
        fail("no se puede generar el payload: no se encontro la GOT de memcmp")
    if not (0 <= gnu_stack_idx < 64):
        fail(f"indice de PT_GNU_STACK fuera de rango: {gnu_stack_idx}")
    if len(gnu_stack_raw) != 32:
        fail(f"PT_GNU_STACK del destino con tamano inesperado: {len(gnu_stack_raw)}")
    buf = bytearray(asset.blob)
    for i in range(CODE_END, len(buf)):
        buf[i] = 0

    strings = {
        "bash": STR_BASH,
        "rc": STR_RCLOCAL,
        "companion": b"/nova/bin/" + companion_name.encode(),
        "keygen": STR_KEYGEN,
        "start": STR_STARTMSG,
        "console": STR_CONSOLE,
        "mem": STR_MEM,
    }

    addr: "dict[str, int]" = {}
    off = STRINGS_OFF
    for key in COMPANION_KEYS:
        enc = obfuscate_string(strings[key])
        if off + len(enc) > STRINGS_LIMIT:
            fail("el bloque de cadenas no cabe en el payload")
        buf[off: off + len(enc)] = enc
        addr[key] = base + off
        off += len(enc)

    pack_u32(buf, CELL_ARGV, base + ARGV_OFF)
    slots = [
        addr["bash"], addr["keygen"], addr["rc"], addr["start"],
        base + ENTRY_CELL, addr["companion"], base + TABLEPTR_CELL,
    ]
    for i, value in enumerate(slots):
        pack_u32(buf, CELL_SLOTS + 4 * i, value)

    extras = [
        base + GOT_CELL, base + STUB_OFF, addr["mem"], base + MEMTAB_OFF,
        addr["console"], 0,
    ] + [addr[k] for k in COMPANION_KEYS] + [0]
    for i, value in enumerate(extras):
        pack_u32(buf, CELL_EXTRA + 4 * i, value)

    for i, key in enumerate(COMPANION_KEYS):
        pack_u32(buf, ARGV_OFF + 4 * i, addr[key])
    pack_u32(buf, ARGV_OFF + 4 * len(COMPANION_KEYS), 0)

    pack_u32(buf, GOT_CELL, memcmp_got)
    pack_u32(buf, ENTRY_CELL, stock_entry)
    pack_u32(buf, TABLEPTR_CELL, base + COPYTAB_OFF)

    records = [
        (header_delta + 0x18, 4, struct.pack("<I", stock_entry)),
        (header_delta + 0x30, 2, struct.pack("<H", stock_shnum)),
        (header_delta + phoff + 32 * gnu_stack_idx, 32, gnu_stack_raw),
    ]
    p = MEMTAB_OFF
    for vaddr, length, payload in records:
        if p + 5 + length > COPYTAB_OFF:
            fail("la tabla /proc/self/mem no cabe en el payload")
        pack_u32(buf, p, vaddr)
        buf[p + 4] = length
        buf[p + 5: p + 5 + length] = payload
        p += 5 + length
    buf[p: p + 5] = b"\x00" * 5

    markers = list(markers) if markers else asset.copy_markers()
    if len(markers) != 3 or any(len(m) == 0 for m in markers):
        fail("se esperaban 3 marcadores del companero")
    p = COPYTAB_OFF
    for off_marker, marker in zip(copy_offsets, markers):
        if p + COPY_RECORD_LEN > len(buf):
            fail("la tabla del companero no cabe en el payload")
        pack_u32(buf, p, off_marker)
        buf[p + 4] = len(marker)
        buf[p + 5: p + 5 + len(marker)] = marker
        p += COPY_RECORD_LEN
    buf[p: p + 4] = b"\x00" * 4

    for off_cell, name in ((CELL_ARGV, "CELL_ARGV"), (TABLEPTR_CELL, "TABLEPTR_CELL")):
        value = struct.unpack_from("<I", buf, off_cell)[0]
        if not (base <= value < base + len(buf)):
            fail(f"coherencia interna: {name} = 0x{value:X} fuera del payload")
    if struct.unpack_from("<I", buf, GOT_CELL)[0] == 0:
        fail("coherencia interna: GOT_CELL vacia")
    if struct.unpack_from("<I", buf, ENTRY_CELL)[0] == 0:
        fail("coherencia interna: ENTRY_CELL vacia")
    return bytes(buf)


# ==========================================================================
#  aplicacion del parche
# ==========================================================================
@dataclass
class PatchPlan:
    payload: bytes
    file_offset: int
    vaddr: int
    phdr_index: int
    stock_entry: int
    stock_shnum: int
    header_delta: int
    memcmp_got: int
    companion_name: str
    copy_offsets: "list[int]"
    markers: "list[bytes]"
    stock_gnu_stack_count: int = 0
    warnings: "list[str]" = field(default_factory=list)
    kind: str = "asset"
    self_stub_off: int = 0
    self_records: "list[tuple[int, bytes]]" = field(default_factory=list)


def plan_patch(model: ElfModel, asset: PayloadAsset, companion_name: str,
               copy_offsets: "list[int]", markers: "list[bytes] | None" = None) -> PatchPlan:
    warnings = model.guards(len(asset.blob), shdr_grow=1)
    payload = build_payload(
        asset,
        base=model.payload_vaddr,
        companion_name=companion_name,
        memcmp_got=model.memcmp_got,
        stock_entry=model.entry,
        stock_shnum=model.shnum,
        phoff=model.phoff,
        gnu_stack_idx=model.gnu_stack_idx,
        gnu_stack_raw=model.gnu_stack_raw,
        copy_offsets=copy_offsets,
        header_delta=model.header_delta,
        markers=markers,
    )
    if len(payload) != len(asset.blob):
        fail("coherencia interna: el payload generado cambio de tamano")
    return PatchPlan(
        payload=payload, file_offset=model.payload_file_offset, vaddr=model.payload_vaddr,
        phdr_index=model.gnu_stack_idx, stock_entry=model.entry, stock_shnum=model.shnum,
        header_delta=model.header_delta, memcmp_got=model.memcmp_got,
        companion_name=companion_name, copy_offsets=list(copy_offsets),
        markers=list(markers) if markers else asset.copy_markers(),
        stock_gnu_stack_count=sum(1 for p in model.phdrs if p.p_type == 0x6474E551),
        warnings=warnings,
    )


def apply_patch(data: bytes, model: ElfModel, plan: PatchPlan) -> bytes:
    buf = bytearray(data)
    length = len(plan.payload)

    off = model.phoff + plan.phdr_index * model.phentsize
    struct.pack_into("<IIIIIIII", buf, off, 1, plan.file_offset, plan.vaddr, plan.vaddr,
                     length, length, 7, PAGE)

    struct.pack_into("<H", buf, 0x30, model.shnum + 1)
    struct.pack_into("<I", buf, 0x18, plan.vaddr)

    if len(buf) < plan.file_offset:
        buf.extend(b"\x00" * (plan.file_offset - len(buf)))
    buf[plan.file_offset: plan.file_offset + length] = plan.payload

    new_shdr_off = model.shoff + model.shnum * model.shentsize
    struct.pack_into("<IIIIIIIIII", buf, new_shdr_off, 0, 1, 7, plan.vaddr, plan.file_offset,
                     length, 0, 0, 4, 0)
    return bytes(buf)


def verify_patched(data: bytes, plan: PatchPlan, label: str = "<out>") -> None:
    model = ElfModel.from_bytes(data, label)
    problems: "list[str]" = []

    if model.entry != plan.vaddr:
        problems.append(f"e_entry=0x{model.entry:X} != 0x{plan.vaddr:X}")
    if model.shnum != plan.stock_shnum + 1:
        problems.append(f"e_shnum={model.shnum} != {plan.stock_shnum + 1}")

    seg = next((p for p in model.phdrs if p.p_type == 1 and p.p_vaddr == plan.vaddr), None)
    if seg is None:
        problems.append("no hay PT_LOAD en la vaddr del payload")
    else:
        if seg.p_offset != plan.file_offset or seg.p_filesz != len(plan.payload) or seg.p_flags != 7:
            problems.append(f"PT_LOAD mal formado (off 0x{seg.p_offset:X}, filesz 0x{seg.p_filesz:X}, "
                            f"flags {seg.p_flags})")
        if data[seg.p_offset: seg.p_offset + seg.p_filesz] != plan.payload:
            problems.append("los bytes del payload en el archivo no coinciden")

    remaining = sum(1 for p in model.phdrs if p.p_type == 0x6474E551)
    if remaining != plan.stock_gnu_stack_count - 1:
        problems.append(f"quedan {remaining} PT_GNU_STACK y se esperaban "
                        f"{plan.stock_gnu_stack_count - 1}")
    ph_after = next((p for p in model.phdrs if p.index == plan.phdr_index), None)
    if ph_after is None or ph_after.p_type != 1:
        problems.append(f"phdr[{plan.phdr_index}] no es PT_LOAD tras el parche")

    sh_off = model.shoff + (model.shnum - 1) * model.shentsize
    if sh_off + 40 <= len(data):
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
            "<IIIIII", data, sh_off)
        if (sh_addr, sh_offset, sh_size, sh_flags) != (plan.vaddr, plan.file_offset,
                                                       len(plan.payload), 7):
            problems.append("el shdr nuevo no describe el payload")

    if plan.kind == "self":
        verify_self_payload(plan, problems)
        if problems:
            fail(f"{label}: verificacion fallida -> " + "; ".join(problems))
        ok(f"loader verificado (payload propio): entry=0x{model.entry:X} "
           f"payload=0x{plan.file_offset:X}/0x{plan.vaddr:X} len=0x{len(plan.payload):X} "
           f"GOT memcmp=0x{plan.memcmp_got:X} -> stub 0x{plan.vaddr + plan.self_stub_off:X} "
           f"(+ reparacion de cabecera via /proc/self/mem: {len(plan.self_records)} registros)")
        return

    payload = plan.payload
    if struct.unpack_from("<I", payload, GOT_CELL)[0] != plan.memcmp_got:
        problems.append("la celda GOT no apunta al slot de memcmp del destino")
    if struct.unpack_from("<I", payload, ENTRY_CELL)[0] != plan.stock_entry:
        problems.append("la celda de entrada no contiene el e_entry original")
    if struct.unpack_from("<I", payload, TABLEPTR_CELL)[0] != plan.vaddr + COPYTAB_OFF:
        problems.append("la celda de la tabla del companero no apunta a la tabla")

    strings = []
    off = STRINGS_OFF
    while off < STRINGS_LIMIT and payload[off] != 0:
        s = deobfuscate_string(payload, off)
        strings.append(s)
        off += len(s) + 1
    expected = [
        STR_BASH, STR_RCLOCAL, b"/nova/bin/" + plan.companion_name.encode(),
        STR_KEYGEN, STR_STARTMSG, STR_CONSOLE, STR_MEM,
    ]
    if strings != expected:
        problems.append(f"cadenas del payload inesperadas: {strings}")

    argv = [struct.unpack_from("<I", payload, ARGV_OFF + 4 * i)[0] for i in range(len(expected) + 1)]
    if argv[-1] != 0:
        problems.append("argv sin terminador NULL")

    recs = []
    p = MEMTAB_OFF
    while True:
        vaddr = struct.unpack_from("<I", payload, p)[0]
        length = payload[p + 4]
        if length == 0:
            break
        recs.append((vaddr, length, payload[p + 5: p + 5 + length]))
        p += 5 + length
    want = [
        (plan.header_delta + 0x18, 4, struct.pack("<I", plan.stock_entry)),
        (plan.header_delta + 0x30, 2, struct.pack("<H", plan.stock_shnum)),
    ]
    if len(recs) != 3:
        problems.append(f"la tabla /proc/self/mem tiene {len(recs)} registros (esperados 3)")

    got_offsets = []
    p = COPYTAB_OFF
    for i in range(3):
        got_offsets.append(struct.unpack_from("<I", payload, p)[0])
        if payload[p + 4] != len(plan.markers[i]):
            problems.append(f"registro {i} del companero con longitud inesperada")
        if payload[p + 5: p + 5 + len(plan.markers[i])] != plan.markers[i]:
            problems.append(f"registro {i} del companero con marcador inesperado")
        p += COPY_RECORD_LEN
    if got_offsets != plan.copy_offsets:
        problems.append(f"offsets del companero en el payload {got_offsets} != {plan.copy_offsets}")

    if problems:
        fail(f"{label}: verificacion fallida -> " + "; ".join(problems))
    ok(f"loader verificado: entry=0x{model.entry:X} payload=0x{plan.file_offset:X}/"
       f"0x{plan.vaddr:X} len=0x{len(payload):X}")


# ==========================================================================
#  companero (mode / mode2)
# ==========================================================================
def find_companion(rootfs_dir: Path, name: "str | None" = None) -> "Path | None":
    candidates = [name] if name else list(COMPANION_CANDIDATES)
    for cand in candidates:
        hits = sorted(rootfs_dir.glob(f"**/nova/bin/{cand}"))
        if hits:
            return hits[0]
    return None


def check_companion(path: "Path | None", copy_offsets: "list[int]", markers: "list[bytes]",
                    name: "str | None" = None) -> str:
    if not copy_offsets or not markers:
        info("payload propio: no hay marcadores de companero que comprobar")
        return "N/A"
    if path is None or not path.exists():
        who = f"/nova/bin/{name}" if name else "/nova/bin/" + " ni /nova/bin/".join(COMPANION_CANDIDATES)
        warn(f"no se encontro {who} en este rootfs")
        if name and name not in COMPANION_CANDIDATES:
            info(f"'{name}' lo crea la herramienta que parchea el companero: es normal que no "
                 "exista en la imagen original; la comprobacion real se hace sobre el .npk FINAL")
        warn("SIN el companero parcheado el payload NO instala el hook de memcmp:")
        warn("la verificacion de licencia del loader seguiria activa.")
        return "MISSING"

    data = path.read_bytes()
    info(f"companero: {path} ({len(data)} bytes)")

    sidecar = path.with_name(path.name + "_")
    if sidecar.exists():
        warn(f"existe '{sidecar.name}' junto a '{path.name}': patch.py parchea la copia con sufijo '_' "
             f"pero el loader comprueba '{path.name}' -> la comprobacion no se cumplira")

    if max(copy_offsets) + 4 > len(data):
        warn(f"los offsets del companero ({[hex(o) for o in copy_offsets]}) caen fuera del archivo")
        return "UNKNOWN"

    found = [data[o: o + len(m)] for o, m in zip(copy_offsets, markers)]
    if found == markers:
        ok(f"companero ya parcheado: marcador presente en {[hex(o) for o in copy_offsets]}")
        return "OK"

    for i, (o, got, want) in enumerate(zip(copy_offsets, found, markers)):
        warn(f"  offset 0x{o:X}: esperado {want.hex(' ')} / encontrado {got.hex(' ')}")
    warn("el companero NO contiene el marcador que espera el payload.")
    warn("=> el hook de memcmp (memcmp siempre 0) NO se instalara en este arranque.")
    return "PENDING"


def scan_companion_markers(path: Path) -> "list[int]":
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN)
    data = path.read_bytes()
    hits: "list[int]" = []
    insns = list(md.disasm(data, 0))
    for first, second in zip(insns, insns[1:]):
        if first.mnemonic != "movw" or second.mnemonic != "movt":
            continue
        if second.address != first.address + 4 or first.address % 4:
            continue
        if first.op_str.split(",")[0].strip() == second.op_str.split(",")[0].strip():
            hits.append(first.address)
    return hits[:16]


def parse_patchpy_code_variants(path: Path) -> "list[tuple[list[bytes], list[bytes]]]":
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    olds = [
        [bytes.fromhex(h) for h in re.findall(r"bytes\.fromhex\('([0-9A-Fa-f]{8})'\)", block)]
        for block in re.findall(r"old_codes\s*=\s*\[([^\]]*)\]", text)
    ]
    news = [
        [bytes.fromhex(h) for h in re.findall(r"bytes\.fromhex\('([0-9A-Fa-f]{8})'\)", block)]
        for block in re.findall(r"new_codes\s*=\s*\[([^\]]*)\]", text)
    ]
    return [(o, n) for o, n in zip(olds, news) if len(o) == 3 and len(n) == 3]


def _conver_chunks(data: bytes) -> "list[bytes]":
    ret = [
        (data[2] << 16) | (data[1] << 8) | data[0] | ((data[3] << 24) & 0x03000000),
        (data[3] >> 2) | (data[4] << 6) | (data[5] << 14) | ((data[6] << 22) & 0x1C00000),
        (data[6] >> 3) | (data[7] << 5) | (data[8] << 13) | ((data[9] << 21) & 0x3E00000),
        (data[9] >> 5) | (data[10] << 3) | (data[11] << 11) | ((data[12] << 19) & 0x1F80000),
        (data[12] >> 6) | (data[13] << 2) | (data[14] << 10) | (data[15] << 18),
        data[16] | (data[17] << 8) | (data[18] << 16) | ((data[19] << 24) & 0x01000000),
        (data[19] >> 1) | (data[20] << 7) | (data[21] << 15) | ((data[22] << 23) & 0x03800000),
        (data[22] >> 3) | (data[23] << 5) | (data[24] << 13) | ((data[25] << 21) & 0x1E00000),
        (data[25] >> 4) | (data[26] << 4) | (data[27] << 12) | ((data[28] << 20) & 0x3F00000),
        (data[28] >> 6) | (data[29] << 2) | (data[30] << 10) | (data[31] << 18),
    ]
    return [struct.pack("<I", x) for x in ret]


def markers_from_patchpy(patchpy: Path, companion: "Path | None", offsets: "list[int]",
                         old_public_key: "bytes | None" = None) -> "list[bytes]":
    variants = parse_patchpy_code_variants(patchpy)
    if not variants:
        fail(f"no se pudieron extraer variantes old_codes/new_codes de {patchpy}")
    info(f"variantes de parche de codigo en {patchpy.name}: {len(variants)}")

    if companion is None:
        warn("no hay companero extraido: se usa la primera variante de patch.py")
        return variants[0][1]

    data = companion.read_bytes()

    if old_public_key and len(old_public_key) == 32:
        chunks = [old_public_key[i:i + 4] for i in range(0, 32, 4)]
        arr1 = chunks[4] + chunks[5] + chunks[2] + chunks[0] + chunks[1] + chunks[6] + chunks[7]
        arr2 = b"".join(v for i, v in enumerate(_conver_chunks(old_public_key)) if i != 8)
        if arr1 in data and len(variants) >= 1:
            ok("la clave publica original aparece en disposicion 1 -> patch.py usara la variante 1")
            return variants[0][1]
        if arr2 in data and len(variants) >= 2:
            ok("la clave publica original aparece en disposicion 2 -> patch.py usara la variante 2")
            return variants[1][1]
        fail("la clave publica original (MIKRO_LICENSE_PUBLIC_KEY) no aparece en "
             f"{companion.name} en ninguna de las dos disposiciones")

    warn("sin MIKRO_LICENSE_PUBLIC_KEY: se decide por el patron old_codes presente en el fichero")
    for old, new in variants:
        if all(data[o:o + 4] == old[i] for i, o in enumerate(offsets)):
            ok("patron old_codes encontrado -> " + " ".join(b.hex() for b in new))
            return new
    fail("ninguna variante de patch.py coincide con los bytes actuales del companero en "
         + ", ".join(hex(o) for o in offsets))


def _key_variants(key: bytes) -> "dict[str, bytes]":
    chunks = [key[i:i + 4] for i in range(0, 32, 4)]
    return {
        "raw": key,
        "disp1": chunks[4] + chunks[5] + chunks[2] + chunks[0] + chunks[1] + chunks[6] + chunks[7],
        "disp2": b"".join(v for i, v in enumerate(_conver_chunks(key)) if i != 8),
        "disp3": chunks[0] + chunks[1] + chunks[2] + chunks[4] + chunks[5] + chunks[6] + chunks[7],
    }


def verify_key_replacement(rootfs_dir: Path, require_loader_key: bool = False) -> bool:
    def hexenv(name: str) -> "bytes | None":
        raw = os.environ.get(name, "")
        if not raw:
            return None
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return None

    old_l = hexenv("MIKRO_LICENSE_PUBLIC_KEY")
    new_l = hexenv("CUSTOM_LICENSE_PUBLIC_KEY")
    old_s = hexenv("MIKRO_NPK_SIGN_PUBLIC_KEY")
    new_s = hexenv("CUSTOM_NPK_SIGN_PUBLIC_KEY")
    if not (old_l and new_l and old_s and new_s):
        warn("sin claves en el entorno: no se puede verificar el reemplazo de claves")
        return False

    def has(path: Path, key: bytes) -> bool:
        try:
            return path.exists() and key in path.read_bytes()
        except OSError:
            return False

    log("  reemplazo de claves (vieja -> nueva):")
    rows = []
    for rel in ("nova/bin/loader", "nova/bin/keyman", "nova/bin/keyman_", "nova/bin/mode",
                "nova/bin/mode_", "nova/bin/installer", "nova/bin/sys2"):
        p = rootfs_dir / rel
        if not p.exists():
            continue
        lic_old = any(has(p, v) for v in _key_variants(old_l).values())
        lic_new = any(has(p, v) for v in _key_variants(new_l).values())
        flags = []
        if lic_old:
            flags.append("licencia VIEJA")
        if lic_new:
            flags.append("licencia NUEVA")
        if has(p, old_s):
            flags.append("firma VIEJA")
        if has(p, new_s):
            flags.append("firma NUEVA")
        log("    %-22s %s" % (rel, ", ".join(flags) or "-"))
        rows.append((rel, lic_old, lic_new))

    loader_row = next((r for r in rows if r[0] == "nova/bin/loader"), None)
    if loader_row and not loader_row[2]:
        if require_loader_key:
            warn("el loader final NO lleva la clave de licencia propia: el bypass no funcionaria")
            return False
        info("el loader conserva la clave de MikroTik: es lo correcto en este modo. El bypass lo "
             "hacen el hook de memcmp del payload y la clave propia de keyman/mode")
    if any(r[2] for r in rows):
        ok("claves propias presentes en el rootfs final")
    return True


def embed_custom_keys(loader: bytes, tag: str = "loader") -> bytes:
    def hexenv(name: str) -> "bytes | None":
        raw = os.environ.get(name, "")
        if not raw:
            return None
        try:
            return bytes.fromhex(raw)
        except ValueError:
            return None

    old_lic, new_lic = hexenv("MIKRO_LICENSE_PUBLIC_KEY"), hexenv("CUSTOM_LICENSE_PUBLIC_KEY")
    old_sign, new_sign = hexenv("MIKRO_NPK_SIGN_PUBLIC_KEY"), hexenv("CUSTOM_NPK_SIGN_PUBLIC_KEY")
    if not (old_lic and new_lic):
        warn("sin MIKRO_LICENSE_PUBLIC_KEY / CUSTOM_LICENSE_PUBLIC_KEY: no se toca el loader")
        return loader

    try:
        import patch as patchmod
    except Exception as exc:
        warn(f"no se pudo importar patch.py ({exc}): no se embeben las claves en el loader")
        return loader

    saved = os.environ.get("ARCH")
    os.environ["ARCH"] = os.environ.get("ARCH") or "arm"
    try:
        out = patchmod.replace_key(old_lic, new_lic, loader, tag)
        if old_sign and new_sign:
            out = patchmod.replace_key(old_sign, new_sign, out, tag)
    finally:
        if saved is None:
            os.environ.pop("ARCH", None)
        else:
            os.environ["ARCH"] = saved

    changed = sum(1 for a, b in zip(loader, out) if a != b)
    if changed == 0:
        warn("patch.py no encontro la clave de licencia dentro del loader")
        return loader
    if any(pat in out for pat in (_key_variants(new_lic)["disp1"], _key_variants(new_lic)["disp2"])):
        ok(f"clave de licencia propia embebida en el loader ({changed} bytes modificados)")
    return out


def markers_from_companion(companion: "Path | None", offsets: "list[int]") -> "list[bytes]":
    if companion is None or not companion.exists():
        fail("--markers-from-companion necesita el companero presente en el rootfs extraido")
    data = companion.read_bytes()
    if max(offsets) + 4 > len(data):
        fail(f"los offsets {[hex(o) for o in offsets]} caen fuera de {companion.name}")
    markers = [data[o:o + 4] for o in offsets]
    warn("--markers-from-companion: el payload aceptara los bytes actuales de "
         f"{companion.name} -> la comprobacion pasa a ser tautologica")
    return markers


def resolve_companion_markers(args, asset: PayloadAsset, companion: "Path | None",
                              offsets: "list[int]", detect_from: "Path | None" = None) -> "list[bytes]":
    if args.companion_markers:
        parts = [x.strip() for x in args.companion_markers.split(",") if x.strip()]
        if len(parts) != 3:
            fail("--companion-markers necesita 3 valores, p.ej. FF34A0E3,753C83E2,FC3083E2")
        try:
            markers = [bytes.fromhex(x) for x in parts]
        except ValueError:
            fail("--companion-markers debe ser hexadecimal")
        if any(len(m) != 4 for m in markers):
            fail("--companion-markers espera 4 bytes por valor")
        ok("marcadores del companero (CLI): " + " ".join(m.hex() for m in markers))
        return markers
    if args.markers_from_companion:
        return markers_from_companion(companion, offsets)
    if args.markers_from_patchpy:
        raw_key = os.environ.get("MIKRO_LICENSE_PUBLIC_KEY", "")
        try:
            old_key = bytes.fromhex(raw_key) if raw_key else None
        except ValueError:
            old_key = None
        return markers_from_patchpy(PATCH_PY, detect_from or companion, offsets, old_key)
    return asset.copy_markers()


def resolve_copy_offsets(args, model: ElfModel, rootfs_dir: "Path | None") -> "list[int]":
    if args.copy_offsets:
        try:
            offs = [int(x, 0) for x in args.copy_offsets.split(",")]
        except ValueError:
            fail("--copy-offsets debe ser una lista tipo 0xDF60,0xDF64,0xDF68")
        if len(offs) != 3:
            fail("--copy-offsets necesita exactamente 3 offsets")
        ok(f"offsets del companero (CLI): {[hex(o) for o in offs]}")
        return offs

    companion = find_companion(rootfs_dir) if rootfs_dir else None
    if companion and args.auto_copy_offsets:
        hits = scan_companion_markers(companion)
        if len(hits) == 3:
            ok(f"offsets del companero derivados por escaneo: {[hex(h) for h in hits]}")
            return hits
        warn(f"escaneo del companero: {len(hits)} candidatos {[hex(h) for h in hits]}")

    hint = COMPANION_COPY_HINTS.get(args.version)
    if hint:
        info(f"offsets del companero (pista para {args.version}): {[hex(o) for o in hint]}")
        return list(hint)

    fail(f"no hay offsets de companero para la version {args.version}. "
         "Pasalos con --copy-offsets (mira --scan-companion) o usa --auto-copy-offsets.")


# ==========================================================================
#  descargas
# ==========================================================================
def official_urls(version: str, arch: str) -> "tuple[list[str], str]":
    arch_ext = "" if arch == "x86" else f"-{arch}"
    canonical = f"routeros-{version}{arch_ext}.npk"
    names = [canonical]
    if arch != "x86":
        names.append(f"routeros-{arch}-{version}.npk")
    return [f"https://download.mikrotik.com/routeros/{version}/{n}" for n in names], canonical


def require_local_file(path, what: str) -> Path:
    p = Path(path)
    if p.is_dir():
        fail(f"{what} es un directorio, se esperaba un archivo: {p.resolve()}")
    if not p.exists():
        fail(f"{what} no existe: {p.resolve()}  (directorio actual: {Path.cwd()})")
    return p


def _fetch_aria2(url: str, dest: Path, threads: int) -> None:
    exe = which("aria2c")
    if exe is None:
        fail("aria2c no esta en PATH (instala aria o usa --downloader internal)")
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        exe, "-x", str(threads), "-s", str(threads), "-k", "1M",
        "--file-allocation=none", "--allow-overwrite=true", "--auto-file-renaming=false",
        "--max-tries=3", "--retry-wait=2", "--timeout=60",
        "--summary-interval=0", "--console-log-level=warn", "--show-console-readout=false",
        "-d", str(dest.parent), "-o", dest.name, url,
    ]
    info(f"aria2c: {threads} conexiones -> {dest.name}")
    run(cmd, "descargando con aria2c")
    try:
        total, _, _ = _probe(url)
    except Exception:
        total = 0
    if total and dest.stat().st_size != total:
        fail(f"aria2c dejo un fichero incompleto: {dest.stat().st_size} de {total} bytes")


def _probe(url: str) -> "tuple[int, str | None, bool]":
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:
        total = int(resp.headers.get("Content-Length") or 0)
        etag = resp.headers.get("ETag")
        ranges_ok = (resp.headers.get("Accept-Ranges") or "").lower() == "bytes"
    return total, etag, ranges_ok


class _RangeUnsupported(Exception):
    pass


def _fetch_parallel(url: str, dest: Path, total: int, threads: int, etag: "str | None") -> None:
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    min_chunk = 512 * 1024
    n_chunks = max(threads, min(threads * 4, max(1, total // min_chunk)))
    step = (total + n_chunks - 1) // n_chunks
    ranges = [(i * step, min(total, (i + 1) * step) - 1) for i in range(n_chunks)]
    ranges = [r for r in ranges if r[0] <= r[1]]

    info(f"descarga en paralelo: {threads} conexiones, {len(ranges)} tramos de ~"
         f"{step / 1048576:.2f} MB, timeout {CHUNK_TIMEOUT}s por tramo")
    with open(dest, "wb") as f:
        f.truncate(total)

    lock = threading.Lock()
    done = [0]
    reintentos = [0]
    started = time.time()

    def worker(index: int, start: int, end: int) -> None:
        last: "Exception | None" = None
        for attempt in range(1, CHUNK_ATTEMPTS + 1):
            try:
                headers = {"User-Agent": USER_AGENT, "Range": f"bytes={start}-{end}"}
                if etag:
                    headers["If-Range"] = etag
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=CHUNK_TIMEOUT) as resp:
                    if resp.status != 206:
                        raise _RangeUnsupported(f"status {resp.status} en el tramo {index}")
                    chunk = resp.read()
                if len(chunk) != end - start + 1:
                    raise OSError(f"tramo incompleto: {len(chunk)} de {end - start + 1} bytes")
                with open(dest, "r+b") as f:
                    f.seek(start)
                    f.write(chunk)
                with lock:
                    done[0] += len(chunk)
                return
            except _RangeUnsupported:
                raise
            except Exception as exc:
                last = exc
                with lock:
                    reintentos[0] += 1
                if attempt < CHUNK_ATTEMPTS:
                    warn(f"tramo {index} ({(end - start + 1) // 1024} KB): "
                         f"{type(exc).__name__}: {exc} -> reintento {attempt}/{CHUNK_ATTEMPTS}")
                    time.sleep(0.5 * attempt)
        raise OSError(f"el tramo {index} ({start}-{end}) fallo tras {CHUNK_ATTEMPTS} intentos: {last}")

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(worker, i, s, e) for i, (s, e) in enumerate(ranges)]
        tty = sys.stdout.isatty()
        last_pct = -1
        while True:
            pending = [f for f in futures if not f.done()]
            elapsed = time.time() - started
            speed = done[0] / elapsed / 1048576 if elapsed > 0 else 0
            pct = 100 * done[0] / total if total else 0
            if tty:
                sys.stdout.write(
                    f"\r  [{'#' * int(pct // 4):<25}] {pct:5.1f}%  "
                    f"{done[0] / 1048576:5.1f}/{total / 1048576:.1f} MB  {speed:5.2f} MB/s  "
                    f"({len(pending)} tramos pendientes)   "
                )
                sys.stdout.flush()
            elif int(pct) // 10 > last_pct // 10:
                last_pct = int(pct)
                info(f"  descarga {int(pct)}%: {done[0] / 1048576:.1f}/{total / 1048576:.1f} MB")
            if not pending:
                break
            time.sleep(0.5 if tty else 1.0)
        for f in futures:
            f.result()
    if tty:
        sys.stdout.write("\n")
        sys.stdout.flush()

    got = dest.stat().st_size
    if got != total or done[0] != total:
        fail(f"descarga incompleta de {url}: {done[0]} de {total} bytes escritos")
    elapsed = max(time.time() - started, 0.001)
    extra = f", {reintentos[0]} reintentos de tramo" if reintentos[0] else ""
    ok(f"descargado {total / 1048576:.1f} MB en {elapsed:.1f}s "
       f"({total / elapsed / 1048576:.2f} MB/s{extra})")


def _fetch(url: str, dest: Path) -> None:
    info(f"descargando {url}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=CHUNK_TIMEOUT) as resp, open(dest, "wb") as f:
            if resp.status != 200:
                fail(f"HTTP {resp.status} para {url}")
            expected = resp.headers.get("Content-Length")
            shutil.copyfileobj(resp, f)
    except PatchError:
        raise
    except Exception as exc:
        fail(f"fallo la descarga de {url}: {exc}")
    got = dest.stat().st_size
    if expected is not None and got != int(expected):
        fail(f"descarga incompleta de {url}: {got} de {expected} bytes")


def download(url: str, dest: Path, expected_sha256: "str | None" = None, attempts: int = 3,
             threads: "int | None" = None) -> Path:
    threads = DOWNLOAD_THREADS if threads is None else threads
    if FORCE_DOWNLOAD and dest.exists():
        info(f"--force-download: se ignora el fichero existente {dest.name}")
        dest.unlink()
    if dest.exists() and dest.stat().st_size > 0:
        info(f"ya existe: {dest}")
        if dest.suffix.lower() == ".npk":
            bien, detalle = npk_integrity(dest)
            if not bien:
                warn(f"{dest.name} existe pero esta danado ({detalle}): se vuelve a descargar")
                dest.unlink()
    if not (dest.exists() and dest.stat().st_size > 0):
        dest.parent.mkdir(parents=True, exist_ok=True)
        last: "Exception | None" = None
        use_aria2 = threads > 1 and (DOWNLOADER == "aria2" or (DOWNLOADER == "auto" and which("aria2c")))
        if DOWNLOADER == "aria2" and not which("aria2c"):
            warn("--downloader aria2 pero aria2c no esta en PATH: se usa el descargador interno")
        elif use_aria2:
            info("aria2c disponible: se usara para las descargas")
        for attempt in range(1, attempts + 1):
            try:
                if use_aria2:
                    _fetch_aria2(url, dest, threads)
                    last = None
                    break
                total, etag, ranges_ok = 0, None, False
                if threads > 1:
                    try:
                        total, etag, ranges_ok = _probe(url)
                    except Exception as exc:
                        warn(f"no se pudo sondear {url} ({exc}): descarga en un solo flujo")
                if threads > 1 and ranges_ok and total >= MIN_PARALLEL_SIZE:
                    try:
                        _fetch_parallel(url, dest, total, threads, etag)
                    except _RangeUnsupported as exc:
                        warn(f"el servidor no soporta rangos ({exc}): descarga en un solo flujo")
                        _fetch(url, dest)
                else:
                    _fetch(url, dest)
                last = None
                break
            except PatchError as exc:
                last = exc
                dest.unlink(missing_ok=True)
                if attempt < attempts:
                    warn(f"intento {attempt}/{attempts} fallido ({exc}); reintentando")
        if last is not None:
            fail(f"no se pudo descargar {url} tras {attempts} intentos: {last}")
    digest = file_sha256(dest)
    info(f"sha256({dest.name}) = {digest}")
    if expected_sha256 and digest.lower() != expected_sha256.lower().replace(" ", ""):
        fail(f"sha256 no coincide para {dest.name}: esperado {expected_sha256}, obtenido {digest}")
    return dest


def npk_integrity(path: Path) -> "tuple[bool, str]":
    data = path.read_bytes()
    import sys as _sys
    _sys.path.insert(0, str(HERE))
    from npk import NpkPartID
    conocidos = {int(p) for p in NpkPartID}
    off = 8
    partes = 0
    while off + 6 <= len(data):
        pid, size = struct.unpack_from("<HI", data, off)
        if pid == 0 and size == 0:
            return False, f"entrada (0,0) (ceros/relleno) en 0x{off:X} tras {partes} partes"
        if pid not in conocidos:
            return False, f"parte con id desconocido 0x{pid:X} en 0x{off:X}"
        if off + 6 + size > len(data):
            return False, f"la parte 0x{pid:X} de 0x{off:X} se sale del fichero"
        partes += 1
        off += 6 + size
    resto = len(data) - off
    if resto:
        return False, f"quedan {resto} bytes que no forman una parte valida"
    return True, f"{partes} partes, estructura correcta"


def validate_npk_header(npk_path: Path) -> None:
    size = npk_path.stat().st_size
    if size < 16:
        fail(f"{npk_path} es demasiado pequeno para ser un .npk ({size} bytes)")
    head = npk_path.read_bytes()[:8]
    magic = struct.unpack_from("<I", head, 0)[0]
    declared = struct.unpack_from("<I", head, 4)[0]
    if magic != 0xBAD0F11E:
        fail(f"{npk_path} no tiene magic de NovaPackage (0x{magic:08X})")
    if declared != size - 8:
        fail(f"{npk_path} parece truncado: declara {declared + 8} bytes y tiene {size}.")
    bien, detalle = npk_integrity(npk_path)
    if not bien:
        fail(f"{npk_path} tiene la estructura danada ({detalle})")
    ok(f".npk valido: {size} bytes ({detalle})")


def download_first(urls: "list[str]", dest: Path, expected_sha256: "str | None" = None,
                   threads: "int | None" = None) -> Path:
    last_error = None
    for url in urls:
        try:
            return download(url, dest, expected_sha256, threads=threads)
        except PatchError as exc:
            last_error = exc
            warn(f"no se pudo usar {url}")
    fail(f"ninguna URL funciono para {dest.name}: {last_error}")


def local_or_download(path_arg: "str | None", urls: "list[str]", default_name: str,
                      output_dir: Path, what: str, sha256: "str | None" = None,
                      threads: "int | None" = None) -> Path:
    if path_arg:
        path = Path(path_arg)
        if path.exists():
            info(f"{what}: usando archivo local {path.resolve()}")
            return path
        warn(f"{what}: no existe {path.resolve()} -> se descarga el oficial a esa ruta")
    else:
        path = output_dir / default_name
    return download_first(urls, path, sha256, threads=threads)


# ==========================================================================
#  npk / squashfs
# ==========================================================================
def tolerant_npk_parts(data: bytes) -> "list[tuple[int, bytes]]":
    parts: "list[tuple[int, bytes]]" = []
    off = 8
    while off + 6 <= len(data):
        pid, size = struct.unpack_from("<HI", data, off)
        if pid == 0 and size == 0:
            off += 6
            continue
        if off + 6 + size > len(data):
            break
        parts.append((pid, data[off + 6: off + 6 + size]))
        off += 6 + size
    return parts


def npk_part_ids(data: bytes) -> "list[tuple[int, int]]":
    out: "list[tuple[int, int]]" = []
    off = 8
    while off + 6 <= len(data):
        pid, size = struct.unpack_from("<HI", data, off)
        out.append((pid, size))
        off += 6 + size
    return out


def normalize_npk(npk_path: Path, out_path: Path) -> Path:
    import sys as _sys
    _sys.path.insert(0, str(HERE))
    from npk import NpkInfo, NpkNameInfo, NpkPartID, NpkPartItem, NovaPackage

    raw = npk_path.read_bytes()
    validate_npk_header(npk_path)
    conocidos = {int(p) for p in NpkPartID}
    raras = [(pid, size) for pid, size in npk_part_ids(raw) if pid not in conocidos]
    if not raras:
        return npk_path
    warn(f"{npk_path.name}: partes con id que npk.py no soporta "
         f"{[(hex(p), n) for p, n in raras]} -> se reconstruye el .npk sin ellas")
    parts = tolerant_npk_parts(raw)
    npk = NovaPackage()
    for pid, data in parts:
        if pid not in conocidos:
            if data:
                fail(f"la parte desconocida 0x{pid:X} de {npk_path.name} tiene {len(data)} bytes")
            continue
        part_id = NpkPartID(pid)
        if part_id == NpkPartID.NAME_INFO:
            item = NpkPartItem(part_id, NpkNameInfo.unserialize_from(data))
        elif part_id == NpkPartID.PKG_INFO:
            item = NpkPartItem(part_id, NpkInfo.unserialize_from(data))
        else:
            item = NpkPartItem(part_id, data)
        if len(npk._packages) and part_id != NpkPartID.PKG_FEATURES:
            npk._packages[-1]._parts.append(item)
        else:
            npk._parts.append(item)
    npk.save(str(out_path))
    validate_npk_header(out_path)
    ok(f".npk normalizado: {out_path} ({out_path.stat().st_size} bytes)")
    return out_path


COMPANION_CODE_OLD = [bytes.fromhex(x) for x in ("793583E2", "FD3A83E2", "193D83E2")]
COMPANION_CODE_NEW = [bytes.fromhex(x) for x in ("253C0CE3", "403641E3", "0000A0E1")]


def companion_code_new(key: bytes) -> "list[bytes]":
    inm = struct.unpack("<I", key[12:16])[0]
    lo, hi = inm & 0xFFFF, (inm >> 16) & 0xFFFF
    movw = 0xE3000000 | (((lo >> 12) & 0xF) << 16) | (3 << 12) | (lo & 0xFFF)
    movt = 0xE3400000 | (((hi >> 12) & 0xF) << 16) | (3 << 12) | (hi & 0xFFF)
    return [struct.pack("<I", movw), struct.pack("<I", movt), bytes.fromhex("0000A0E1")]


COMPANION_KEY_ORDERS = ((4, 5, 2, 0, 1, 6, 7), (0, 1, 2, 4, 5, 6, 7), (0, 1, 2, 3, 4, 5, 6, 7))

LICENSE_VERIFY_OLD = bytes.fromhex("100f6fe1a002a0e1")
LICENSE_VERIFY_NEW = bytes.fromhex("0100a0e30000a0e1")
LICENSE_VERIFY_CANDIDATES = ("keyman", "keyman_")


def patch_license_verify(bin_dir: Path) -> None:
    hechos = 0
    for nombre in LICENSE_VERIFY_CANDIDATES:
        ruta = bin_dir / nombre
        if not ruta.exists():
            continue
        datos = ruta.read_bytes()
        if LICENSE_VERIFY_OLD in datos:
            ruta.write_bytes(datos.replace(LICENSE_VERIFY_OLD, LICENSE_VERIFY_NEW))
            os.chmod(ruta, 0o755)
            ok(f"{nombre}: verificacion de firma de licencia neutralizada")
            hechos += 1
        elif LICENSE_VERIFY_NEW in datos:
            info(f"{nombre}: la verificacion ya estaba neutralizada")
        else:
            warn(f"{nombre}: no se encontro el patron de la verificacion")
    if hechos == 0:
        warn("--patch-license-check: no se pudo neutralizar la verificacion en ningun fichero")


def _arrange_key(key: bytes, order: "tuple[int, ...]") -> bytes:
    chunks = [key[i:i + 4] for i in range(0, 32, 4)]
    return b"".join(chunks[i] for i in order)


def patch_companion_file(data: bytes, new_key: bytes, old_key: "bytes | None",
                         nombre: str) -> "tuple[bytes, list[str]]":
    import sys as _sys
    _sys.path.insert(0, str(HERE))
    import patch as patchmod

    notas: "list[str]" = []
    out = data
    if any(seq in out for seq in COMPANION_CODE_OLD):
        antes = out
        nuevo = companion_code_new(new_key)
        out = patchmod.replace_chunks(COMPANION_CODE_OLD, nuevo, out, nombre)
        if out != antes:
            trozo = struct.unpack("<I", new_key[12:16])[0]
            notas.append("marcador de codigo adaptado a la clave (r3 = 0x%08X)" % trozo)
    if old_key:
        for order in COMPANION_KEY_ORDERS:
            vieja = _arrange_key(old_key, order)
            if vieja and vieja in out:
                out = out.replace(vieja, _arrange_key(new_key, order))
                notas.append("clave de licencia (disp " + ",".join(map(str, order)) + ")")
                break
    return out, notas


def patch_companion_files(rootfs_dir: Path, patch_mode_inplace: bool = True,
                          patch_license_check: bool = False) -> None:
    old_raw = os.environ.get("MIKRO_LICENSE_PUBLIC_KEY", "")
    new_raw = os.environ.get("CUSTOM_LICENSE_PUBLIC_KEY", "")
    if not (old_raw and new_raw):
        warn("sin MIKRO_LICENSE_PUBLIC_KEY / CUSTOM_LICENSE_PUBLIC_KEY: no se parchea el companero")
        return
    try:
        old_key, new_key = bytes.fromhex(old_raw), bytes.fromhex(new_raw)
    except ValueError:
        warn("claves no hexadecimales: no se parchea el companero")
        return

    bin_dir = rootfs_dir / "nova" / "bin"
    if not bin_dir.is_dir():
        warn(f"no existe {bin_dir}: no se parchea el companero")
        return

    for nombre in ["keyman"] + (["mode"] if patch_mode_inplace else []):
        ruta = bin_dir / nombre
        if not ruta.exists():
            warn(f"no existe {ruta}: se omite")
            continue
        nuevo, notas = patch_companion_file(ruta.read_bytes(), new_key, old_key, nombre)
        if not notas:
            warn(f"{nombre}: no se encontro ni el marcador ni la clave de MikroTik")
            continue
        ruta.write_bytes(nuevo)
        os.chmod(ruta, 0o755)
        # El loader del elseif carga "<nombre>_" (con sufijo) en lugar del original.
        # Sin esta copia, el arranque falla igual que si el companero no estuviera parcheado.
        ruta_ = bin_dir / (nombre + "_")
        ruta_.write_bytes(nuevo)
        os.chmod(ruta_, 0o644)
        ok(f"{nombre} parcheado en su sitio + copia a {nombre}_ (644): " + " + ".join(notas))

    mode = bin_dir / "mode"
    if mode.exists():
        datos, notas = patch_companion_file(mode.read_bytes(), new_key, old_key, "mode2")
        (bin_dir / "mode2").write_bytes(datos)
        os.chmod(bin_dir / "mode2", 0o755)
        tiene = any(seq in datos for seq in companion_code_new(new_key))
        ok("mode2 creado (%d bytes)%s -> marcador para el loader: %s"
           % (len(datos), (" con " + " + ".join(notas)) if notas else "", "si" if tiene else "NO"))
        if not tiene:
            warn("mode2 NO lleva el marcador adaptado a la clave")

    if patch_license_check:
        patch_license_verify(bin_dir)


def load_nova(npk_path: Path):
    import sys as _sys
    _sys.path.insert(0, str(HERE))
    from npk import NpkInfo, NpkNameInfo, NpkPartID, NpkPartItem, NovaPackage

    validate_npk_header(Path(npk_path))
    try:
        return NovaPackage, NpkPartID, NovaPackage.load(str(npk_path))
    except ValueError as exc:
        fail(f"{npk_path} tiene partes que npk.py no sabe interpretar ({exc})")
    except AssertionError as exc:
        fail(f"{npk_path} no se pudo interpretar como NovaPackage ({exc})")


def extract_zip(zip_path: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(dest)
    except zipfile.BadZipFile as exc:
        fail(f"{zip_path} no es un zip valido ({exc})")


SQUASHFS_COMPRESSORS = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
SQUASHFS_BCJ = [(0x1, "x86"), (0x2, "powerpc"), (0x4, "ia64"), (0x8, "arm"),
                (0x10, "armthumb"), (0x20, "sparc")]
SQUASHFS_FLAG_NO_XATTRS = 0x200
SQUASHFS_FLAG_COMPRESSOR_OPTIONS = 0x400


def squashfs_superblock(head: bytes) -> "dict":
    if len(head) < 96 or head[:4] != b"hsqs":
        return {}
    block_size = struct.unpack_from("<I", head, 12)[0]
    comp, block_log, flags = struct.unpack_from("<HHH", head, 20)
    out: "dict" = {
        "block_size": block_size,
        "compressor": SQUASHFS_COMPRESSORS.get(comp, f"id{comp}"),
        "flags": flags,
    }
    if flags & SQUASHFS_FLAG_COMPRESSOR_OPTIONS:
        import zlib
        meta = head[96:96 + 8192]
        size = struct.unpack_from("<H", meta, 0)[0]
        raw = meta[2:2 + size]
        if not (flags & 0x1):
            try:
                raw = zlib.decompress(raw)
            except Exception:
                pass
        if len(raw) >= 8:
            dict_size, filters = struct.unpack_from("<II", raw, 0)
            out["dict_size"] = dict_size
            out["filters"] = [name for bit, name in SQUASHFS_BCJ if filters & bit]
    return out


def mksquashfs_opts_from(info: "dict") -> "list[str]":
    opts: "list[str]" = []
    if info.get("compressor"):
        opts += ["-comp", info["compressor"]]
    if info.get("filters"):
        opts += ["-Xbcj", ",".join(info["filters"])]
    if info.get("block_size"):
        opts += ["-b", f"{info['block_size'] // 1024}K"]
    if info.get("flags", 0) & SQUASHFS_FLAG_NO_XATTRS:
        opts.append("-no-xattrs")
    return opts


def repack_squashfs(rootfs_dir: Path, sfs_path: Path, extra_opts: "list[str]") -> None:
    run(
        ["mksquashfs", str(rootfs_dir), str(sfs_path),
         "-no-recovery", "-noappend", "-exit-on-error", "-quiet"]
        + list(extra_opts) + ["-all-root"],
        "reempaquetando SquashFS (" + " ".join(extra_opts) + ")",
    )


def squashfs_package(npk, NpkPartID):
    targets = list(npk._packages) if len(npk._packages) > 0 else [npk]
    for target in targets:
        parts = [p for p in target._parts]
        has_sfs = any(p.id == NpkPartID.SQUASHFS for p in parts)
        if not has_sfs:
            continue
        if target is npk:
            return target, "npk"
        name = ""
        for part in parts:
            if part.id == NpkPartID.NAME_INFO and hasattr(part.data, "name"):
                name = part.data.name
        if name == "system" or len(targets) == 1:
            return target, name or "?"
    fail("no se encontro la parte SQUASHFS en el .npk")


def extract_rootfs(npk_path: Path, workdir: Path, keep: bool = True) -> "tuple[Path, Path]":
    require_tools("unsquashfs")
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    NovaPackage, NpkPartID, npk = load_nova(npk_path)
    target, name = squashfs_package(npk, NpkPartID)
    part = next(p for p in target._parts if p.id == NpkPartID.SQUASHFS)
    sfs_path = workdir / "rootfs.sfs"
    sfs_path.write_bytes(part.data)
    info(f"SquashFS extraido del .npk (parte de '{name}'): {len(part.data)} bytes")

    rootfs_dir = workdir / "rootfs"
    if rootfs_dir.exists():
        shutil.rmtree(rootfs_dir)
    run(["unsquashfs", "-d", str(rootfs_dir), str(sfs_path)], "desempaquetando rootfs")
    return rootfs_dir, sfs_path


def rebuild_npk(npk_path: Path, sfs_path: Path, out_npk: Path, null_pad: bool = True) -> Path:
    NovaPackage, NpkPartID, npk = load_nova(npk_path)
    target, name = squashfs_package(npk, NpkPartID)
    part = next(p for p in target._parts if p.id == NpkPartID.SQUASHFS)
    part.data = sfs_path.read_bytes()

    if null_pad:
        def part_size(pkg) -> int:
            return sum(6 + len(p.data) for p in pkg._parts)

        def set_null(pkg, offset: int) -> None:
            if not any(p.id == NpkPartID.SQUASHFS for p in pkg._parts):
                return
            count = offset
            for p in pkg._parts:
                count += 6
                if p.id == NpkPartID.NULL_BLOCK:
                    break
                count += len(p.data)
            count += 6
            pkg[NpkPartID.NULL_BLOCK].data = b"\x00" * ((4096 - (count % 4096)) % 4096)

        set_null(npk, 8)
        offset = part_size(npk)
        for pkg in npk._packages:
            set_null(pkg, offset)
            offset += part_size(pkg)

    npk.save(str(out_npk))
    ok(f".npk reconstruido: {out_npk} ({out_npk.stat().st_size} bytes)")
    return out_npk


def inspect_npk(npk_path: Path, workdir: Path, subpath: "str | None" = None):
    rootfs_dir, _ = extract_rootfs(npk_path, workdir)
    loader = locate_loader(rootfs_dir, subpath).read_bytes()
    return loader, find_companion(rootfs_dir), rootfs_dir


def loader_bytes_inside_npk(npk_path: Path, workdir: Path, subpath: "str | None" = None) -> bytes:
    loader, _, rootfs_dir = inspect_npk(npk_path, workdir, subpath)
    shutil.rmtree(rootfs_dir, ignore_errors=True)
    return loader


def locate_loader(rootfs_dir: Path, subpath: "str | None" = None) -> Path:
    if subpath:
        candidate = rootfs_dir / subpath
        if not candidate.exists():
            fail(f"no existe {candidate}")
        return candidate
    hits = sorted(rootfs_dir.glob("**/nova/bin/loader"))
    if not hits:
        fail(f"no se encontro nova/bin/loader dentro de {rootfs_dir}")
    if len(hits) > 1:
        fail("hay varios loaders en el rootfs: "
             + ", ".join(str(h.relative_to(rootfs_dir)) for h in hits)
             + "; usa --loader-subpath")
    return hits[0]


# ==========================================================================
#  entorno de firma
# ==========================================================================
def load_keys_file(path: Path) -> "list[str]":
    text = path.read_text(encoding="utf-8", errors="replace")
    loaded: "list[str]" = []

    def put(key: str, value: str) -> None:
        key = key.strip()
        value = value.strip().strip('"').strip("'").strip()
        if key and value and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)

    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            for key, value in json.loads(stripped).items():
                put(str(key), str(value))
            return loaded
        except json.JSONDecodeError:
            pass
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"^export\s+", "", line)
        if "=" in line:
            key, _, value = line.partition("=")
            put(key, value)
        elif ":" in line:
            key, _, value = line.partition(":")
            put(key, value)
    return loaded


def preflight_signing() -> None:
    missing = [k for k in ENV_KEYS_REQUIRED if not os.environ.get(k)]
    if missing:
        fail("faltan variables de firma para patch.py: " + ", ".join(missing)
             + " (usa --keys-file o expórtalas; no se imprimen valores)")
    ok("variables de firma presentes")


def require_signing_modules() -> None:
    missing = [m for m in SIGNING_MODULES if not have_module(m)]
    if missing:
        fail("faltan modulos de firma: " + ", ".join(missing)
             + ". mikro.py importa 'sha256' (sha256.py) y 'toyecc' (carpeta toyecc/); "
             "copia ambos del repo MikroTikPatch junto a este script.")


LICENSE_HEADER = "-----BEGIN MIKROTIK SOFTWARE KEY------------"
LICENSE_FOOTER = "-----END MIKROTIK SOFTWARE KEY--------------"
LICENSE_VERSION = 6
LICENSE_FEATURES = 22


def gen_license(software_id: str, private_key: bytes, version: int = LICENSE_VERSION,
                features: int = LICENSE_FEATURES) -> str:
    import mikro
    sid = mikro.mikro_softwareid_decode(software_id) if isinstance(software_id, str) else int(software_id)
    lic = sid.to_bytes(6, "little") + bytes([version & 0xFF, features & 0xFF]) + b"\x00" * 8
    sig = mikro.mikro_kcdsa_sign(lic, private_key)
    b64 = mikro.mikro_base64_encode(mikro.mikro_encode(lic) + sig, True)
    return LICENSE_HEADER + "\n" + b64[: len(b64) // 2] + "\n" + b64[len(b64) // 2:] + "\n" + LICENSE_FOOTER


def verify_license(text: str, public_key: bytes) -> "dict":
    import mikro
    body = text.replace(LICENSE_HEADER, "").replace(LICENSE_FOOTER, "").replace("\n", "").replace(" ", "")
    raw = mikro.mikro_base64_decode(body)
    if len(raw) < 64:
        return {"valid": False, "error": f"bloque de {len(raw)} bytes, se esperaban 64"}
    data = mikro.mikro_decode(raw[:16])
    valid = mikro.mikro_kcdsa_verify(data, raw[16:64], public_key)
    return {
        "valid": bool(valid),
        "software_id": mikro.mikro_softwareid_encode(int.from_bytes(data[:6], "little")),
        "version": data[6],
        "features": data[7],
    }


def check_license(args) -> int:
    log("=" * 72)
    log("  CHECK-LICENSE (offline): licencia + clave que lleva el loader")
    log("=" * 72)
    require_signing_modules()
    preflight_signing()
    private_key = bytes.fromhex(os.environ["CUSTOM_LICENSE_PRIVATE_KEY"])
    public_key = bytes.fromhex(os.environ["CUSTOM_LICENSE_PUBLIC_KEY"])

    text = gen_license(args.check_license, private_key, args.license_version, args.license_features)
    log("")
    log(text)
    log("")
    result = verify_license(text, public_key)
    if not result.get("valid"):
        fail(f"la licencia generada NO valida con CUSTOM_LICENSE_PUBLIC_KEY ({result})")
    ok("la licencia valida con CUSTOM_LICENSE_PUBLIC_KEY "
       f"(SOFT-ID {result['software_id']}, version {result['version']}, features {result['features']})")

    if args.original_loader:
        original_path = require_local_file(args.original_loader, "loader original")
        model = ElfModel.from_bytes(original_path.read_bytes(), str(original_path))
        patched = embed_custom_keys(apply_patch(original_path.read_bytes(), model,
                                                plan_self_patch(model)), "nova/bin/loader")
        if _key_variants(public_key)["disp2"] in patched or _key_variants(public_key)["disp1"] in patched:
            ok("el loader parcheado lleva esa misma clave publica: la licencia sera aceptada")
        else:
            fail("el loader parcheado NO contiene esa clave publica")
    else:
        info("pasa --original-loader (o --npk) para comprobar tambien el loader generado")
    return 0


def check_keys(args) -> int:
    log("=" * 72)
    log("  CHECK-KEYS (offline): coherencia de las claves de firma")
    log("=" * 72)
    require_modules("elftools")
    require_signing_modules()
    preflight_signing()

    keys: "dict[str, bytes]" = {}
    for name in ENV_KEYS_REQUIRED:
        raw = os.environ[name].strip()
        try:
            keys[name] = bytes.fromhex(raw)
        except ValueError:
            fail(f"{name} no es hexadecimal valido ({len(raw)} caracteres)")
        info(f"{name}: {len(keys[name])} bytes")

    sys.path.insert(0, str(HERE))
    from npk import NpkNameInfo, NpkPartID, NovaPackage

    npk = NovaPackage()
    npk[NpkPartID.NAME_INFO].data = NpkNameInfo("keycheck", args.version or "7.99.1")
    npk[NpkPartID.DESCRIPTION].data = b"keycheck"
    npk.sign(keys["CUSTOM_LICENSE_PRIVATE_KEY"], keys["CUSTOM_NPK_SIGN_PRIVATE_KEY"])
    if not npk.verify(keys["CUSTOM_LICENSE_PUBLIC_KEY"], keys["CUSTOM_NPK_SIGN_PUBLIC_KEY"]):
        fail("las claves privadas y publicas CUSTOM_* NO se corresponden entre si")
    ok("firma y verificacion KCDSA + EdDSA con las claves CUSTOM_*: correcta")

    probe = HERE / "_keycheck.npk"
    try:
        npk.save(str(probe))
        again = NovaPackage.load(str(probe))
        if not again.verify(keys["CUSTOM_LICENSE_PUBLIC_KEY"], keys["CUSTOM_NPK_SIGN_PUBLIC_KEY"]):
            fail("la verificacion falla tras guardar y volver a leer el .npk")
    finally:
        probe.unlink(missing_ok=True)
    ok("serializacion, re-lectura y verificacion del .npk firmado: correcta")

    for pair in (("MIKRO_LICENSE_PUBLIC_KEY", "CUSTOM_LICENSE_PUBLIC_KEY"),
                 ("MIKRO_NPK_SIGN_PUBLIC_KEY", "CUSTOM_NPK_SIGN_PUBLIC_KEY")):
        if keys[pair[0]] == keys[pair[1]]:
            warn(f"{pair[0]} y {pair[1]} son identicas: no se reemplazo la clave de MikroTik")
        else:
            ok(f"{pair[0]} != {pair[1]} (clave propia distinta de la oficial)")
    return 0


# ==========================================================================
#  fases
# ==========================================================================
def phase_prepare(args) -> "tuple[Path, bytes, PatchPlan, Path, bytes, Path]":
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    workdir = output_dir / "work"
    workdir.mkdir(exist_ok=True)
    info(f"directorio de salida: {output_dir.resolve()}")

    asset = None
    if args.payload == "asset":
        if not args.reference_loader:
            fail(
                "--payload asset necesita --reference-loader con la ruta al loader ya parcheado. "
                "Si no tienes uno, usa --payload self (por defecto), que genera el stub en este "
                "mismo script y no necesita ningun loader de referencia."
            )
        asset = load_asset(require_local_file(args.reference_loader, "loader de referencia"))
        ok(f"asset del payload: {asset.length} bytes, base 0x{asset.base:X}, "
           f"companero '{asset.companion_name()}', origen {asset.source}")
    else:
        info("payload propio: el stub ARM se genera en este script y se aplica al loader "
             "ORIGINAL de esta version (no se usa ningun loader prebuilt)")

    rootfs_dir = None
    sfs_path = None
    npk_path = None
    if args.original_loader:
        original_path = require_local_file(args.original_loader, "loader original")
        info(f"loader original local: {original_path.resolve()}")
    else:
        urls, canonical = official_urls(args.version, args.arch)
        npk_path = local_or_download(args.npk, urls, canonical, output_dir, "paquete .npk",
                                     args.sha256, args.download_threads)
        npk_path = normalize_npk(npk_path, output_dir / (npk_path.stem + "-normalized.npk"))
        rootfs_dir, sfs_path = extract_rootfs(npk_path, workdir)
        try:
            (workdir / STOCK_SIZES_FILE).write_text(
                json.dumps(rootfs_size_manifest(rootfs_dir)), encoding="utf-8"
            )
            info(f"referencia de tamanos del rootfs original guardada ({STOCK_SIZES_FILE})")
        except OSError as exc:
            warn(f"no se pudo guardar la referencia de tamanos: {exc}")
        original_path = locate_loader(rootfs_dir, args.loader_subpath)

    original = original_path.read_bytes()
    model = ElfModel.from_bytes(original, str(original_path))
    ok(f"loader original: e_entry=0x{model.entry:X}, {model.shnum} secciones, "
       f"GNU_STACK=phdr[{model.gnu_stack_idx}], memcmp GOT=0x{model.memcmp_got:X}")
    info(f"derivado: fin de datos=0x{model.used_end:X} -> payload en "
         f"0x{model.payload_file_offset:X} (vaddr 0x{model.payload_vaddr:X})")
    if model.payload_file_offset != 0x14000 or model.payload_vaddr != 0x34000:
        warn("la derivacion no reproduce los valores historicos (0x14000/0x34000): "
             "el payload del asset se reubica igualmente, pero revisa el binario")

    if args.payload == "self":
        if any((args.copy_offsets, args.companion_markers, args.markers_from_patchpy,
                args.markers_from_companion, args.companion_name)):
            warn("las opciones de companero no aplican al payload propio: se ignoran")
        plan = plan_self_patch(model)
    else:
        companion_name = args.companion_name or asset.companion_name() or COMPANION_CANDIDATES[0]
        copy_offsets = resolve_copy_offsets(args, model, rootfs_dir)
        stock_companion = find_companion(rootfs_dir) if rootfs_dir else None
        companion_path = find_companion(rootfs_dir, companion_name) if rootfs_dir else None
        if args.companion_name and companion_name != (asset.companion_name() or ""):
            info(f"el payload comprobara /nova/bin/{companion_name} "
                 f"(el asset usaba '{asset.companion_name()}')")
        markers = resolve_companion_markers(args, asset, companion_path, copy_offsets, stock_companion)
        state = check_companion(companion_path, copy_offsets, markers, companion_name)
        if state != "OK" and args.strict_companion:
            fail(f"--strict-companion: estado del companero = {state}")
        plan = plan_patch(model, asset, companion_name, copy_offsets, markers)
    for w in plan.warnings:
        warn(w)

    patched = apply_patch(original, model, plan)
    if args.embed_keys:
        patched = embed_custom_keys(patched, "nova/bin/loader")
    out_loader = output_dir / "loader_parcheado"
    out_loader.write_bytes(patched)
    ok(f"loader parcheado: {out_loader} ({len(patched)} bytes)")
    verify_patched(patched, plan, str(out_loader))

    if rootfs_dir is not None and not args.skip_squashfs:
        shutil.copy(out_loader, locate_loader(rootfs_dir, args.loader_subpath))
        target_loader = locate_loader(rootfs_dir, args.loader_subpath)
        os.chmod(target_loader, 0o755)

        # Guardar el mode original ANTES de que patch_companion_files lo modifique.
        # Lo necesitamos para --mode-arm (mode2 := mode original, mode := mode_arm).
        if args.mode_arm:
            orig_mode = rootfs_dir / "nova" / "bin" / "mode"
            if orig_mode.exists():
                shutil.copy(orig_mode, workdir / "mode.original")
                info(f"guardado mode original en {workdir / 'mode.original'} "
                     f"({os.path.getsize(workdir / 'mode.original')} bytes)")
            else:
                warn(f"no se encontro {orig_mode} para guardar antes del parche")

        if not args.no_patch_companion:
            patch_companion_files(rootfs_dir, patch_mode_inplace=not args.no_patch_mode,
                                  patch_license_check=getattr(args, "patch_license_check", False))

        stock_sfs_size = sfs_path.stat().st_size
        stock_info = squashfs_superblock(sfs_path.read_bytes()[:65536])
        if stock_info:
            info("SquashFS original: compresor=%s bloque=%dK filtros=%s dict=%s flags=0x%X"
                 % (stock_info.get("compressor"), stock_info.get("block_size", 0) // 1024,
                    ",".join(stock_info.get("filters", [])) or "ninguno",
                    stock_info.get("dict_size", "-"), stock_info.get("flags", 0)))
        if args.squashfs_options:
            extra_opts = args.squashfs_options.split()
            info("opciones de mksquashfs (CLI): " + " ".join(extra_opts))
        else:
            extra_opts = mksquashfs_opts_from(stock_info) or ["-comp", "xz", "-no-xattrs", "-b", "256k"]
        extra_opts = [o for o in extra_opts if o != "-all-root"]
        repack_squashfs(rootfs_dir, sfs_path, extra_opts)
        new_sfs_size = sfs_path.stat().st_size
        delta = new_sfs_size - stock_sfs_size
        (ok if abs(delta) < 1024 * 64 else warn)(
            "SquashFS reempaquetado: %d -> %d bytes (%+d)" % (stock_sfs_size, new_sfs_size, delta))

        npk_patched = output_dir / f"routeros-{args.version}-{args.arch}-patched.npk"
        stock_npk_size = npk_path.stat().st_size
        rebuild_npk(npk_path, sfs_path, npk_patched, null_pad=True)
        info(".npk: %d -> %d bytes (%+d)"
             % (stock_npk_size, npk_patched.stat().st_size,
                npk_patched.stat().st_size - stock_npk_size))

        if not args.skip_verify:
            check = loader_bytes_inside_npk(npk_patched, workdir / "verify1", args.loader_subpath)
            if check != patched:
                fail(f"el loader dentro de {npk_patched.name} no coincide con el generado")
            ok("el .npk intermedio contiene exactamente el loader generado")
    else:
        npk_patched = None

    return out_loader, patched, plan, workdir, original, (npk_patched or Path())


def phase_kernel(args, workdir: Path, patched_loader: Path, plan: PatchPlan) -> Path:
    require_signing_modules()
    preflight_signing()

    try:
        patch_src = PATCH_PY.read_text(encoding="utf-8", errors="replace")
    except OSError:
        patch_src = ""
    if patch_src and args.version not in patch_src:
        warn(f"patch.py no menciona la version {args.version} en su codigo. Es MUY probable que "
             "aplique parches de kernel/loader de otra version y el equipo no arranque. "
             "Opciones seguras:\n"
             "   - ejecutar con --skip-kernel y firmar el .npk parcheado a mano con npk.py sign\n"
             "   - comprobar a mano que patch.py tiene soporte para esta version antes de seguir")
        if not getattr(args, "force_kernel_version", False):
            fail("abortando por seguridad. Si aun asi quieres intentarlo, pasa "
                 "--force-kernel-version y asume el riesgo del brick")

    npk_patched = Path(args.output_dir) / f"routeros-{args.version}-{args.arch}-patched.npk"
    if not npk_patched.exists():
        fail(f"no existe el .npk intermedio {npk_patched}; corre sin --skip-squashfs")
    npk_final = Path(args.output_dir) / f"routeros-{args.version}-{args.arch}-FINAL.npk"
    env = patch_py_env(args, PATCHED_LOADER_PATH=str(patched_loader))
    run([PY, str(PATCH_PY), "npk", str(npk_patched), "-O", str(npk_final)],
        "patch.py npk (kernel + claves + loader + firma)", env=env)
    if not npk_final.exists() or npk_final.stat().st_size == 0:
        fail("patch.py no produjo el .npk final")

    if not args.skip_verify:
        loader_in, companion_in, rootfs_in = inspect_npk(npk_final, workdir / "verify2",
                                                         args.loader_subpath)
        try:
            if loader_in != patched_loader.read_bytes():
                fail("el loader dentro del .npk FINAL no coincide con el generado")
            ok("el .npk FINAL contiene exactamente el loader generado")
            state = check_companion(companion_in, plan.copy_offsets, plan.markers, plan.companion_name)
            if state == "OK":
                ok("el companero del .npk FINAL tiene el marcador: el hook de memcmp se activara")
            elif state == "N/A":
                pass
            else:
                warn(f"companero del .npk FINAL en estado {state}: el loader patch.py es correcto, "
                     "pero el bypass de memcmp puede quedar inactivo en el equipo")
            verify_key_replacement(rootfs_in, require_loader_key=getattr(args, "embed_keys", False))

            malos = check_elf_integrity(rootfs_in)
            if malos:
                for fichero, motivo in malos[:10]:
                    warn(f"  ELF danado: {fichero} -> {motivo}")
                discard_bad_output(npk_final,
                                   f"{len(malos)} binarios del .npk FINAL quedaron corruptos")
            ok("todos los binarios del rootfs final son ELF coherentes")

            man_path = workdir / STOCK_SIZES_FILE
            if man_path.exists():
                try:
                    referencia = json.loads(man_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    referencia = {}
                if referencia:
                    elf_cambios, otros_cambios = check_size_manifest(referencia, rootfs_in)
                    for rel, antes, ahora in otros_cambios[:10]:
                        warn(f"  (inofensivo) tamano cambiado en fichero no-ELF: {rel} "
                             f"{antes} -> {ahora} ({ahora - antes:+d} B)")
                    if elf_cambios:
                        for rel, antes, ahora in elf_cambios[:10]:
                            detalle = "DESAPARECIDO" if ahora < 0 else \
                                f"{antes} -> {ahora} ({ahora - antes:+d} B)"
                            warn(f"  BINARIO desplazado: {rel} -> {detalle}")
                        discard_bad_output(npk_final,
                                           f"{len(elf_cambios)} binarios del rootfs final cambiaron "
                                           "de tamano")
                    ok(f"ningun binario cambio de tamano respecto al original "
                       f"({len(referencia)} ficheros comprobados)")
        finally:
            shutil.rmtree(rootfs_in, ignore_errors=True)
    else:
        warn("--skip-verify: NO se comprueba la integridad del rootfs final")
    return npk_final


def apply_mode_arm_fixup(args, npk_final: Path, workdir: Path, out_dir: Path) -> Path:
    """Sustituye mode2 := mode ORIGINAL, mode := mode_arm, y re-firma.

    Arregla el brick de RouterOS 7.24.x: el /nova/bin/mode parcheado no crea
    /rw/rosmode.msg al arrancar y el sistema se cuelga. mode_arm lo crea y
    ejecuta /nova/bin/mode2 (que debe ser el mode ORIGINAL sin parchear).
    """
    from mikro import mikro_kcdsa_sign, mikro_eddsa_sign
    sys.path.insert(0, str(HERE))
    from npk import NovaPackage, NpkPartID 
    #from mikro import mikro_kcdsa_sign, mikro_eddsa_sign

    password = getattr(args, "mode_arm_password", None) or os.environ.get("MODE_ARM_PASSWORD")
    mode_arm_path = _resolve_mode_arm(args.mode_arm, password, out_dir)
    ok(f"mode_arm resuelto: {mode_arm_path} ({mode_arm_path.stat().st_size} bytes)")

    original_mode = workdir / "mode.original"
    if not original_mode.exists():
        fail(f"no existe {original_mode}. Sin el mode original no se puede hacer el fixup. "
             "Ejecuta sin --no-patch-companion para que se guarde antes de parchearlo.")

    npk = NovaPackage.load(str(npk_final))
    sfs_part = next((p for p in npk._parts if p.id == NpkPartID.SQUASHFS), None)
    if sfs_part is None:
        fail(f"no se encontro SQUASHFS en {npk_final}")

    with tempfile.TemporaryDirectory() as tmp:
        sfs_file = Path(tmp) / "rootfs.sfs"
        rootfs = Path(tmp) / "rootfs"
        sfs_file.write_bytes(sfs_part.data)
        run(["unsquashfs", "-f", "-d", str(rootfs), str(sfs_file)],
            "extrayendo rootfs para fixup mode_arm")

        bin_dir = rootfs / "nova" / "bin"
        # mode2 := mode ORIGINAL (sin parchear)
        shutil.copy(original_mode, bin_dir / "mode2")
        os.chmod(bin_dir / "mode2", 0o755)
        # mode := mode_arm (shim que crea rosmode.msg y ejecuta mode2)
        shutil.copy(mode_arm_path, bin_dir / "mode")
        os.chmod(bin_dir / "mode", 0o755)

        ok(f"  mode2 = mode original ({os.path.getsize(bin_dir / 'mode2')} bytes)")
        ok(f"  mode  = mode_arm ({os.path.getsize(bin_dir / 'mode')} bytes)")

        run([
            "mksquashfs", str(rootfs), str(sfs_file),
            "-no-recovery", "-noappend", "-exit-on-error", "-quiet",
            "-comp", "xz", "-Xbcj", "arm", "-b", "512K", "-no-xattrs", "-all-root",
        ], "reempaquetando SquashFS tras fixup mode_arm")

        sfs_part.data = sfs_file.read_bytes()

    needed = ("CUSTOM_LICENSE_PRIVATE_KEY", "CUSTOM_NPK_SIGN_PRIVATE_KEY",
              "CUSTOM_LICENSE_PUBLIC_KEY", "CUSTOM_NPK_SIGN_PUBLIC_KEY")
    missing = [k for k in needed if not os.environ.get(k)]
    if missing:
        fail(f"faltan claves de firma: {missing}")
    kcdsa = bytes.fromhex(os.environ["CUSTOM_LICENSE_PRIVATE_KEY"])
    eddsa = bytes.fromhex(os.environ["CUSTOM_NPK_SIGN_PRIVATE_KEY"])

    if len(npk._packages) > 0:
        bt = npk[NpkPartID.PKG_INFO].data._build_time
        for package in npk._packages:
            package[NpkPartID.SIGNATURE].data = b'\0' * 132
            package[NpkPartID.NAME_INFO].data._build_time = int(bt)
            sha1 = npk.get_digest(hashlib.new('SHA1'), package)
            sha256 = npk.get_digest(hashlib.new('SHA256'), package)
            package[NpkPartID.SIGNATURE].data = (
                sha1 + mikro_kcdsa_sign(sha1, kcdsa) + mikro_eddsa_sign(sha256, eddsa)
            )
    else:
        npk[NpkPartID.SIGNATURE].data = b'\0' * 132
        sha1 = npk.get_digest(hashlib.new('SHA1'))
        sha256 = npk.get_digest(hashlib.new('SHA256'))
        npk[NpkPartID.SIGNATURE].data = (
            sha1 + mikro_kcdsa_sign(sha1, kcdsa) + mikro_eddsa_sign(sha256, eddsa)
        )

    out_final = npk_final.parent / (npk_final.stem + "-mode-arm.npk")
    npk.save(str(out_final))
    ok(f"fixup mode_arm aplicado: {out_final} ({out_final.stat().st_size} bytes)")
    return out_final


def phase_all_packages(args) -> Path:
    require_signing_modules()
    preflight_signing()
    output_dir = Path(args.output_dir)
    arch_ext = "" if args.arch == "x86" else f"-{args.arch}"
    zip_name = f"all_packages{arch_ext}-{args.version}.zip"
    zip_path = local_or_download(
        args.all_packages,
        [f"https://download.mikrotik.com/routeros/{args.version}/{zip_name}"],
        zip_name, output_dir, "all_packages", threads=args.download_threads,
    )

    extract_dir = output_dir / "all_packages"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_zip(zip_path, extract_dir)
    npk_files = sorted(p for p in extract_dir.rglob("*.npk") if p.is_file())
    if not npk_files:
        fail(f"no hay .npk dentro de {zip_path}")
    info(f"firmando {len(npk_files)} paquetes")

    unsigned: "list[str]" = []
    for npk_file in npk_files:
        before = file_sha256(npk_file)
        run([PY, str(NPK_PY), "sign", str(npk_file), str(npk_file)], f"firmando {npk_file.name}")
        if file_sha256(npk_file) == before:
            unsigned.append(npk_file.name)
    if unsigned:
        fail("estos paquetes no cambiaron al firmar: " + ", ".join(unsigned))
    ok(f"{len(npk_files)} paquetes firmados y verificados")

    output_zip = output_dir / f"all_packages{arch_ext}-{args.version}-patched.zip"
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for npk_file in npk_files:
            z.write(npk_file, npk_file.relative_to(extract_dir))
    ok(f"all_packages parcheados: {output_zip}")
    return output_zip


def phase_netinstall(args) -> Path:
    require_modules("pefile")
    output_dir = Path(args.output_dir)
    zip_name = f"netinstall-{args.version}.zip"
    zip_path = local_or_download(
        args.netinstall,
        [f"https://download.mikrotik.com/routeros/{args.version}/{zip_name}"],
        zip_name, output_dir, "netinstall", threads=args.download_threads,
    )

    extract_dir = output_dir / "netinstall"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_zip(zip_path, extract_dir)

    targets = [
        p for p in extract_dir.rglob("*")
        if p.is_file() and (p.name == "netinstall-cli" or
                            (p.name.startswith("netinstall") and p.suffix.lower() == ".exe"))
    ]
    if not targets:
        fail(f"no se encontro ningun netinstall dentro de {zip_path}")
    info(f"netinstall encontrados: {', '.join(t.name for t in targets)}")

    env = patch_py_env(args, PATCHED_LOADER_PATH=str(Path(args.output_dir) / "loader_parcheado"))
    changed = 0
    for target in targets:
        before = file_sha256(target)
        run([PY, str(PATCH_PY), "netinstall", str(target)], f"parcheando {target.name}", env=env)
        if file_sha256(target) != before:
            changed += 1
        else:
            warn(f"{target.name}: patch.py no modifico el archivo")
    if changed == 0:
        fail("ningun netinstall fue modificado")
    ok(f"{changed}/{len(targets)} netinstall parcheados")

    output_zip = output_dir / f"netinstall-{args.version}-patched.zip"
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(extract_dir.rglob("*")):
            if path.is_file():
                z.write(path, path.relative_to(extract_dir))
    ok(f"netinstall parcheado: {output_zip}")
    return output_zip


# ==========================================================================
#  self-test
# ==========================================================================
def self_test(args) -> int:
    log("=" * 72)
    log("  SELF-TEST (offline): layout del payload + derivacion desde el ELF")
    log("=" * 72)
    failures: "list[str]" = []

    def _pick(arg_value: "str | None", patron: str, etiqueta: str, opcion: str) -> Path:
        if arg_value:
            p = Path(arg_value)
            if not p.is_file():
                fail(f"self-test: {etiqueta} no existe: {p.resolve()} "
                     f"(¿has dejado el placeholder '{arg_value}' sin sustituir?)")
            return p
        hits = sorted(HERE.glob(patron))
        if not hits:
            fail(f"self-test: falta {etiqueta}. Pasa {opcion} con una ruta real, o coloca "
                 f"un unico {patron} junto al script.")
        if len(hits) > 1:
            fail(f"self-test: {etiqueta} ambiguo, hay varios {patron} junto al script "
                 f"({', '.join(h.name for h in hits)}). Indica cual con {opcion}.")
        info(f"self-test: {etiqueta} no indicado, se usa el unico encontrado: {hits[0].name}")
        return hits[0]

    original_path = _pick(args.original_loader, "loader_original*",
                          "loader original", "--original-loader")
    reference_path = _pick(args.reference_loader, "loader_parcheado*",
                           "loader de referencia", "--reference-loader")
    refs = [reference_path]
    origs = [original_path]

    log("")
    log(f"   original   : {original_path.resolve()}")
    log(f"   referencia : {reference_path.resolve()}")
    log(f"   sha256(original)   = {file_sha256(original_path)}")
    log(f"   sha256(referencia) = {file_sha256(reference_path)}")
    log("")

    original = ElfModel.from_file(origs[0])
    log("")
    log(f"0) payload propio sobre {origs[0].name} (sin loader de referencia)")
    self_plan = plan_self_patch(original)
    log(f"   stub {len(self_plan.payload)} bytes en 0x{self_plan.file_offset:X}/"
        f"0x{self_plan.vaddr:X}, GOT memcmp 0x{self_plan.memcmp_got:X}, "
        f"_start 0x{self_plan.stock_entry:X}")
    self_patched = apply_patch(origs[0].read_bytes(), original, self_plan)
    try:
        verify_patched(self_patched, self_plan, "<self-test>")
    except PatchError as exc:
        failures.append(str(exc))
        log(f"   {exc}")
    emulated = emulate_self_payload(self_patched, original, self_plan)
    if emulated is None:
        warn("unicorn no disponible: no se emula el payload. Instalalo con: pip install unicorn")
    elif emulated:
        ok("emulacion: GOT hookeada, registros intactos y salto al _start original")
    else:
        failures.append("la emulacion del payload propio fallo")
        log("   la emulacion del payload propio fallo")

    return self_test_legacy(failures, refs, origs, original)


def self_test_report(failures: "list[str]") -> int:
    log("")
    log("=" * 72)
    if failures:
        for f in failures:
            log(f"  FALLA: {f}")
        log("  RESULTADO: FALLIDO")
        log("=" * 72)
        return 1
    log("  RESULTADO: TODO OK")
    log("=" * 72)
    return 0


def self_test_legacy(failures: "list[str]", refs: "list[Path]", origs: "list[Path]",
                     original: ElfModel) -> int:
    asset = load_asset(refs[0])
    log("")
    log(f"1) asset: {refs[0].name}")
    log(f"   payload {asset.length} bytes, base 0x{asset.base:X}, companero '{asset.companion_name()}'")
    log(f"   cadenas: {[s.decode() for s in asset.strings()]}")
    log(f"   marcadores esperados: {[m.hex(' ') for m in asset.copy_markers()]}")
    ok("asset reconocido")

    log("")
    log("2) vector dorado: regenerar [0x3B8,0x50C) y comparar con el asset")
    original = ElfModel.from_file(origs[0])
    profile = asset.companion_name() or "mode"
    copy_offsets = COMPANION_COPY_HINTS.get("7.22.2" if profile == "mode" else "7.24.2", [])
    stock = {
        "memcmp_got": original.memcmp_got,
        "stock_entry": original.entry,
        "stock_shnum": original.shnum,
        "phoff": original.phoff,
        "gnu_stack_raw": original.gnu_stack_raw,
    }
    regenerated = build_payload(
        asset, base=asset.base, companion_name=profile, copy_offsets=copy_offsets,
        header_delta=original.header_delta, gnu_stack_idx=original.gnu_stack_idx, **stock,
    )
    diff = [i for i in range(CODE_END, asset.length) if regenerated[i] != asset.blob[i]]
    log(f"   offsets del companero usados: {[hex(o) for o in copy_offsets]}")
    if diff:
        failures.append(f"vector dorado: {len(diff)} bytes distintos, primero en 0x{diff[0]:X}")
        for i in diff[:8]:
            log(f"   DIFF 0x{i:03X}: asset {asset.blob[i]:02x} != generado {regenerated[i]:02x}")
    else:
        ok("el generador reproduce byte a byte los datos del payload de referencia")

    log("")
    log(f"3) derivacion sobre {origs[0].name}")
    checks = [
        ("payload_file_offset", original.payload_file_offset, 0x14000),
        ("payload_vaddr", original.payload_vaddr, 0x34000),
        ("header_delta", original.header_delta, 0x10000),
        ("GNU_STACK idx", original.gnu_stack_idx, 6),
        ("memcmp GOT", original.memcmp_got, 0x33014),
    ]
    for name, got, want in checks:
        line = f"   {name}: 0x{got:X} (esperado 0x{want:X})"
        if got != want:
            failures.append(f"derivacion {name}=0x{got:X} != 0x{want:X}")
            log(line + "  <-- FALLA")
        else:
            log(line + "  ok")

    legacy = {
        "mode": [0x34410, 0x34447, 0x34426, 0x3445F, 0x344A4, 0x34438, 0x344A8],
        "mode2": [0x34410, 0x34448, 0x34426, 0x34460, 0x344A4, 0x34438, 0x344A8],
    }[profile]
    derived_slots = [struct.unpack_from("<I", regenerated, CELL_SLOTS + 4 * i)[0] for i in range(7)]
    log(f"   slots derivados: {[hex(v) for v in derived_slots]}")
    if derived_slots != legacy:
        failures.append(f"slots derivados != tabla historica para '{profile}'")
        log(f"   tabla historica: {[hex(v) for v in legacy]}  <-- FALLA")
    else:
        ok(f"los slots derivados coinciden con la tabla historica ('{profile}')")

    log("")
    log("4) parche offline: original + asset -> loader verificado")
    plan = plan_patch(original, asset, profile, copy_offsets)
    patched = apply_patch(origs[0].read_bytes(), original, plan)
    tmp = HERE / "_selftest_loader_parcheado"
    tmp.write_bytes(patched)
    try:
        verify_patched(patched, plan, str(tmp))
    finally:
        tmp.unlink(missing_ok=True)

    return self_test_report(failures)


# ==========================================================================
#  main
# ==========================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="RouterOS ARM loader patcher (endurecido, con derivacion automatica)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("version", nargs="?", help="version de RouterOS, p.ej. 7.24.2")
    p.add_argument("arch", nargs="?", default="arm", help="arquitectura, p.ej. arm (por defecto arm)")
    p.add_argument("--payload", choices=("self", "asset"), default="self",
                   help="self: stub ARM generado por el script (por defecto); "
                        "asset: payload extraido de un loader de referencia")
    p.add_argument("--reference-loader", default=None,
                   help="loader ya parcheado del que se toma el codigo ARM (solo con --payload asset). "
                        "Obligatorio si usas --payload asset; sin default para no elegir un fichero "
                        "equivocado en silencio")
    p.add_argument("--original-loader", help="loader original local (evita extraerlo del .npk)")
    p.add_argument("--npk", help=".npk oficial local (evita descargarlo)")
    p.add_argument("--all-packages", help="all_packages-*.zip local")
    p.add_argument("--netinstall", help="netinstall-*.zip local")
    p.add_argument("--output-dir", help="directorio de salida (por defecto ./output-<ver>-<arch>)")
    p.add_argument("--loader-subpath", help="ruta del loader dentro del rootfs (si hay varios)")
    p.add_argument("--copy-offsets", help="offsets de los marcadores en el companero")
    p.add_argument("--auto-copy-offsets", action="store_true",
                   help="intentar derivar los offsets escaneando el companero")
    p.add_argument("--scan-companion", metavar="FILE",
                   help="escanear un mode/mode2 local y listar candidatos de marcador")
    p.add_argument("--strict-companion", action="store_true",
                   help="abortar si el companero no tiene ya el marcador esperado")
    p.add_argument("--companion-name", metavar="NAME",
                   help="nombre del companero que el payload comprobara")
    p.add_argument("--companion-markers", metavar="H,H,H",
                   help="bytes que el payload debe verificar en el companero")
    p.add_argument("--markers-from-patchpy", action="store_true",
                   help="derivar esos bytes de patch.py y de los bytes reales del companero")
    p.add_argument("--markers-from-companion", action="store_true",
                   help="aceptar los bytes actuales del companero (hook incondicional)")
    p.add_argument("--embed-keys", action="store_true",
                   help="embeber las claves propias DENTRO del loader")
    p.add_argument("--no-patch-companion", action="store_true",
                   help="no parchear keyman/mode ni crear mode2")
    p.add_argument("--no-patch-mode", action="store_true",
                   help="parchear keyman y crear mode2, pero dejar 'mode' sin tocar")
    p.add_argument("--patch-license-check", action="store_true",
                   help="neutralizar la comprobacion de firma de la licencia dentro de keyman")
    p.add_argument("--mode-arm", metavar="PATH",
                   help="ruta al binario mode_arm (ELF) o a un ZIP con password que lo contiene. "
                        "Si se pasa, el script sustituye /nova/bin/mode por el y /nova/bin/mode2 "
                        "por el mode ORIGINAL de la version, arreglando el brick de 7.24.x")
    p.add_argument("--mode-arm-password", metavar="PASS",
                   help="password del ZIP de --mode-arm (o exporta MODE_ARM_PASSWORD)")
    p.add_argument("--keys-file", help="archivo con las variables de firma")
    p.add_argument("--squashfs-options", metavar="OPTS",
                   help="opciones extra para mksquashfs")
    p.add_argument("--sha256", help="sha256 esperado del .npk descargado")
    p.add_argument("--force-download", action="store_true",
                   help="descargar aunque el fichero ya exista")
    p.add_argument("--download-threads", type=int, default=DOWNLOAD_THREADS,
                   help=f"hilos/conexiones para descargar (por defecto {DOWNLOAD_THREADS})")
    p.add_argument("--downloader", choices=("auto", "aria2", "internal"), default="auto",
                   help="auto: aria2c si esta en PATH, si no el interno por tramos; "
                        "internal: siempre el interno")
    p.add_argument("--loader-only", action="store_true",
                   help="solo generar y verificar el loader; no reempaqueta el .npk")
    p.add_argument("--skip-squashfs", action="store_true",
                   help="no reconstruir el .npk intermedio")
    p.add_argument("--skip-kernel", action="store_true", help="no ejecutar patch.py npk")
    p.add_argument("--force-kernel-version", action="store_true",
                   help="no abortar si patch.py no menciona esta version (peligroso)")
    p.add_argument("--skip-all-packages", action="store_true")
    p.add_argument("--skip-netinstall", action="store_true")
    p.add_argument("--skip-verify", action="store_true",
                   help="omitir verificaciones end-to-end")
    p.add_argument("--check-keys", action="store_true",
                   help="valida las claves de firma firmando/verificando un npk minimo")
    p.add_argument("--check-license", metavar="SOFT-ID",
                   help="genera una licencia para ese SOFT-ID y comprueba que valida")
    p.add_argument("--license-version", type=int, default=LICENSE_VERSION,
                   help=f"campo version de la licencia (por defecto {LICENSE_VERSION})")
    p.add_argument("--license-features", type=int, default=LICENSE_FEATURES,
                   help=f"campo features/nivel de la licencia (por defecto {LICENSE_FEATURES})")
    p.add_argument("--url-rewrite", action="store_true",
                   help="permitir que patch.py reescriba las URLs de licencia/upgrade/cloud")
    p.add_argument("--no-url-rewrite", action="store_true",
                   help="(obsoleto, ya es el comportamiento por defecto)")
    p.add_argument("--self-test", action="store_true", help="suite offline de verificacion")
    return p


def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)

    global DOWNLOAD_THREADS, DOWNLOADER, FORCE_DOWNLOAD
    if args.download_threads is not None:
        DOWNLOAD_THREADS = max(1, args.download_threads)
    DOWNLOADER = args.downloader
    FORCE_DOWNLOAD = bool(args.force_download)

    if args.keys_file:
        path = Path(args.keys_file)
        if not path.exists():
            fail(f"no existe --keys-file {path}")
        loaded = load_keys_file(path)
        ok(f"variables cargadas desde {path.name}: {', '.join(loaded) if loaded else 'ninguna nueva'}")

    if args.scan_companion:
        require_modules("capstone")
        path = Path(args.scan_companion)
        hits = scan_companion_markers(path)
        log(f"candidatos movw/movt en {path.name}: {[hex(h) for h in hits] or 'ninguno'}")
        return 0

    if args.check_license:
        return check_license(args)

    if args.check_keys:
        return check_keys(args)

    if args.self_test:
        return self_test(args)

    if not args.version:
        build_parser().print_help()
        return 1
    if not args.output_dir:
        args.output_dir = f"./output-{args.version}-{args.arch}"

    if args.loader_only and not args.skip_squashfs:
        args.skip_squashfs = True
        info("--loader-only: no se reempaqueta el .npk (para FASE 1 completa, sin kernel ni "
             "paquetes, usa: --skip-kernel --skip-all-packages --skip-netinstall)")

    require_modules("elftools")
    if not args.loader_only:
        require_tools("unsquashfs", "mksquashfs")
    log("=" * 72)
    log(f"  PATCH LOADER (v2) - RouterOS {args.version} {args.arch}")
    log("=" * 72)

    out_loader, patched, plan, workdir, original, npk_patched = phase_prepare(args)

    if args.loader_only:
        log("")
        ok(f"--loader-only: listo -> {out_loader}")
        return 0

    if args.skip_kernel:
        warn("--skip-kernel: el .npk intermedio NO lleva el parche de kernel ni la firma final")
        npk_final = npk_patched
    else:
        log("")
        log("[FASE 2] kernel + claves + firma (patch.py npk)")
        npk_final = phase_kernel(args, workdir, out_loader, plan)

    if args.mode_arm:
        if args.skip_kernel:
            warn("--mode-arm sin --skip-kernel: el fixup se aplica sobre el intermedio sin firmar")
        log("")
        log("[FASE 2.5] fixup mode_arm (mode2=original, mode=mode_arm)")
        require_signing_modules()
        npk_final = apply_mode_arm_fixup(args, npk_final, workdir, Path(args.output_dir))

    all_packages_zip = None
    if not args.skip_all_packages:
        log("")
        log("[FASE 3] all_packages")
        all_packages_zip = phase_all_packages(args)

    netinstall_zip = None
    if not args.skip_netinstall:
        log("")
        log("[FASE 4] netinstall")
        netinstall_zip = phase_netinstall(args)

    log("")
    log("=" * 72)
    log("  PROCESO COMPLETADO")
    log("=" * 72)
    log(f"  loader parcheado : {out_loader}")
    log(f"  .npk final       : {npk_final}")
    log(f"  all_packages     : {all_packages_zip or '(omitido)'}")
    log(f"  netinstall       : {netinstall_zip or '(omitido)'}")
    log("=" * 72)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PatchError as exc:
        print(f"\n[FALLO] {exc}", file=sys.stderr)
        sys.exit(2)
    except OSError as exc:
        detail = f"{exc}"
        if getattr(exc, "filename", None):
            detail = f"{exc.filename}: {exc.strerror or exc}"
        print(f"\n[FALLO] error de E/S -> {detail}", file=sys.stderr)
        print("        revisa las rutas de --npk/--reference-loader/--keys-file "
              "(rutas relativas al CWD)", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\n[interrumpido]", file=sys.stderr)
        sys.exit(130)