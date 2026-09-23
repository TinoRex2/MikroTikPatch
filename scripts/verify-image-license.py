#!/usr/bin/env python3
"""Valida SIN HARDWARE que una imagen y una licencia encajan (ARM32 y MIPSBE).

Uso:  python3 verify-image-license.py <imagen.npk> <licencia.key>

Reconstruye la clave publica EFECTIVA que usara el equipo y comprueba la licencia contra
ella con el mismo algoritmo del firmware (mikro.py, validado contra una licencia que un
equipo acepto realmente).

  ARM32  : la clave son 7 trozos de 4 B en keyman (0x69F8, orden 4,5,2,0,1,6,7) mas el 4o
           trozo que aporta el codigo parcheado (movw/movt r3 en 0x6940).
  MIPSBE : la clave son 8 constantes de 32 bits construidas con pares lui+ori, consecutivas
           en el codigo de keyman.
"""
from __future__ import annotations

import io
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import npk as N  # noqa: E402
import mikro  # noqa: E402

H = "-----BEGIN MIKROTIK SOFTWARE KEY------------"
F = "-----END MIKROTIK SOFTWARE KEY--------------"


def _secciones_ejecutables(data: bytes):
    from elftools.elf.elffile import ELFFile

    elf = ELFFile(io.BytesIO(data))
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_LOAD" and (seg["p_flags"] & 1):
            yield seg["p_vaddr"], seg["p_offset"], seg.data()


def _pares_mips(code: bytes, ventana: int = 16):
    res = []
    pend = {}
    for i in range(0, len(code) - 3, 4):
        ins = struct.unpack_from(">I", code, i)[0]
        op = ins >> 26
        rs = (ins >> 21) & 0x1F
        rt = (ins >> 16) & 0x1F
        imm = ins & 0xFFFF
        if op == 0x0F:
            pend[rt] = (i, imm)
        elif op in (0x0D, 0x09) and rs in pend:
            off, hi = pend[rs]
            if i - off <= ventana * 4:
                res.append((off, ((hi & 0xFFFF) << 16) | imm))
            del pend[rs]
    return res


def _es_punto_valido(key: bytes) -> bool:
    try:
        from toyecc import FieldElement, Tools, getcurvebyname

        curve = getcurvebyname("Curve25519")
        x = FieldElement(Tools.bytestoint_le(key), curve.p)
        return ((x ** 3) + (curve.a * x ** 2) + x).sqrt() is not None
    except Exception:
        return False


def clave_arm(keyman: bytes):
    """(clave, descripcion) a partir del blob de ARM32 y del trozo del codigo."""
    blob = keyman[0x69F8:0x69F8 + 28]
    if len(blob) < 28 or blob.count(0) > 20:
        return None, "no hay blob de clave en 0x69F8"
    C4, C5, C2, C0, C1, C6, C7 = [blob[i:i + 4] for i in range(0, 28, 4)]
    movw = struct.unpack("<I", keyman[0x6940:0x6944])[0]
    movt = struct.unpack("<I", keyman[0x6948:0x694C])[0]
    if (movw & 0xFFF00000) != 0xE3000000 or (movt & 0xFFF00000) != 0xE3400000:
        return None, "el codigo de 0x6940 no es el marcador parcheado (movw/movt)"
    lo = ((movw >> 16) & 0xF) << 12 | (movw & 0xFFF)
    hi = ((movt >> 16) & 0xF) << 12 | (movt & 0xFFF)
    C3 = struct.pack("<I", (hi << 16) | lo)
    return C0 + C1 + C2 + C3 + C4 + C5 + C6 + C7, "ARM32 (blob 7 trozos + 4o trozo del codigo)"


def clave_mipsbe(keyman: bytes):
    """(clave, descripcion): 8 constantes lui/ori consecutivas."""
    pares = []
    for _base, _off, code in _secciones_ejecutables(keyman):
        pares += _pares_mips(code)
    pares.sort()
    # buscar una tirada de 8 pares seguidos (separacion pequena entre ellos)
    for i in range(len(pares) - 7):
        run = pares[i:i + 8]
        if all(run[k + 1][0] - run[k][0] <= 0x20 for k in range(7)):
            clave = b"".join(struct.pack(">I", v) for _o, v in run)
            if _es_punto_valido(clave):
                return clave, "MIPSBE (8 constantes lui/ori, offsets 0x%X..0x%X)" % (run[0][0], run[7][0])
    return None, "no encuentro 8 constantes lui/ori consecutivas que formen una clave valida"


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    imagen, lic_path = Path(sys.argv[1]), Path(sys.argv[2])
    pkg = N.NovaPackage.load(str(imagen))
    with tempfile.TemporaryDirectory() as tmp:
        sfs = Path(tmp) / "rootfs.sfs"
        sfs.write_bytes(bytes(pkg[N.NpkPartID.SQUASHFS].data))
        out = Path(tmp) / "root"
        subprocess.run(["unsquashfs", "-q", "-d", str(out), str(sfs)], check=True, capture_output=True)
        km = (out / "nova/bin/keyman").read_bytes()
        # tambien el loader, para informar
        ld = (out / "nova/bin/loader").read_bytes()
    clave, como = None, ""
    if ld[:4] == b"\x7fELF" and ld[5] == 2 and ld[18:20] == b"\x00\x08":
        clave, como = clave_mipsbe(km)
    if clave is None:
        clave, como = clave_arm(km)
    if clave is None:
        print("ERROR: no he podido reconstruir la clave publica (%s)" % como)
        return 1
    print("clave publica efectiva: %s" % clave.hex().upper())
    print("  obtenida de: %s" % como)
    raw = mikro.mikro_base64_decode(lic_path.read_text().replace(H, "").replace(F, "").replace("\n", "").strip())
    data = mikro.mikro_decode(raw[:16])
    sid = mikro.mikro_softwareid_encode(int.from_bytes(data[:6], "little"))
    ok = mikro.mikro_kcdsa_verify(data, raw[16:64], clave)
    print("licencia %s -> software-id %s, version %d, nivel %d" % (lic_path.name, sid, data[6], data[7]))
    print("RESULTADO: la licencia %s con esta imagen" % ("VALIDA" if ok else "NO valida"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
