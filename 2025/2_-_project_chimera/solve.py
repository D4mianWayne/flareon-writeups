#!/usr/bin/env python3
"""
extract_catalyst.py

Safe extraction helper for the CTF "Genetic Sequencer" blob.

WHAT IT DOES (SAFE):
 - Loads your top-level marshalled code object (from a zlib+marshal blob)
   OR scans a provided code object bytes file for large encoded constants.
 - Searches constants for large strings/bytes and attempts decoding chains:
     [ascii85 / base85 / base64] -> zlib.decompress -> marshal.loads
 - If a marshal.loads yields a code object it writes a valid .pyc (with header)
   to disk (sequencer_recovered.pyc). It never execs the recovered code object.

USAGE:
 - Put your top-level `encrypted_sequencer_data` bytes into this script (variable at top)
 - Run: python3 extract_catalyst.py
 - It writes results into the current directory and prints suggestions.

Dependencies: none beyond Python stdlib.
"""

import zlib, marshal, importlib.util, struct, time, sys, os
from types import CodeType
import base64
import binascii

# Paste your decompressed/sequenced bytes here OR put the top-level zlib blob and
# the script will zlib.decompress() it.
# Option A: you have the top-level zlib blob (the one originally called encrypted_sequencer_data)
encrypted_sequencer_data = None
# Option B: if you've already decompressed and have the raw marshalled bytes, set this:
# sequencer_marshal_bytes = b'...'
sequencer_marshal_bytes = None

# If both are None, the script will error; set one of them.
# If you already used the analyzer to dump the "disassembly" & constants, you can
# provide the large encoded string directly in the list below as a fallback:
fallback_candidates = [
    # paste the big encoded string constants here as plain Python bytes/str if needed
    # Example:
    b"c$|e+O>7&-6`m!Rzak~llE|2<;!(^*VQn#qEH||xE2b$*W=zw8NW~2mgIMj3sFjzy%<NJQ84^$vqeTG&mC+yhlE677j-8)F4nD>~?<GqL64olvBs$bZ4{qE;{|=p@M4Abeb^*>CzIprJ_rCXLX1@k)54$HHULnIe5P-l)Ahj!*6w{D~l%XMwDPu#jDYhX^DN{q5Q|5-Wq%1@lBx}}|vN1p~UI8h)0U&nS13Dg}x8K^E-(q$p0}4!ly-%m{0Hd>^+3*<O{*s0K-lk|}BLHWKJweQrNz5{%F-;@E_{d+ImTl7-o7&}O{%uba)w1RL*UARX*79t+0<^B?zmlODX9|2bzp_ztwjy_TdKb)1%eP4d-Xti0Ygjk_%w!^%1xuMNv4Z8&(*Ue7_^Fby1n3;+G<VDAfqi^h1>0@=Eki5!M~rms%afx`+uxa0*;FzudpqNln5M<@!OqndZ)R<vh4u&gpmmnaMewbT0RJby?(fa7XW#r>ZQ4UE&u|~lZsEY~-lpfWMf0_+pV-H`PXInpwmyo~mZ`tfUK?($KHa%mvNlovZ;Y)D+e6uw+mY6LNB2Y9&akbWpZ@lh=Si<!J@t|CG86E`)jp!l4xEY(h7@$llA4}B9dpL*j)eL{vVcbyMx5_{b13)N@wa~epS8Zfo&V_Y#fM*g9;@6%j=%i%WB0=QS3ewj@0~B!iibu<MqrrJIH{m&FoAGB3#0Nf;x!~dvQ|9#3c})IL6kEvhByJvA{B9%UqX0Tg*-+Ak~NW&RJbB?a6weENW&rzRi2ZB!647HWlA^rG4gvj3Yteo30&*};59;7nJF7eh7vjEXwwxPWWzD*3<IvZS#lIL(l*?u$;EGifKfLDpVb*rXLyw!AP~ZT^-S=4X{31tqe<O1kwG$gBZnu8eva3~6;4CxrcH1{Qg{M;GT5@Bdqt%s{xkT;DyaBk)v>cTr#=XM@cQ-VZZJ1azh{1Df~fwf(mdYk_cEC``#zrevUuf1-I7DHKqx9c7Me?*iNur9a3~o)A1AmHbK!6#k<d+QmXjoUlrAc=R-8EfEvn$TP%?Zb2%`-;wF2Z7c~Qh!QUp%@F7d(Q;It@nl31iwc^NCTTrj*OW)bEH>BYlQ$YmihSV2QDxrCsKNToEmsNif~;-ILG+l$@~sMDcnEHYIbjb?L-swo%>NNY60QJ5`2LX(&$CFf*W(cl7t80939@QH+>;!kK4jMTiOQA}zM@dS+wmk4?RtsqIs(NtuZr(Ewj<zxXaVots!6<}UP5>nNp1gfkes4T*zd{)6h-GF4>NSQO}R*91{c`k!=D-D}baN$1fuVNrUDvGiYVXWYBI456{mCG`ukuZfpN)A<xyb=s}byE(DvZfmpRkvo4CMg+F*3C%f6#?m{g@T4u-G<~mB~wGXg;NVMFDj&f5<)qG1#7xlYdFEQ_jHRu*e&FUmQ1J<Gp}4$xq@yalC(x)S-FIEgQe+IxARLJPRm@DXx&t+<h5L0ORJ<E<cw}6ln6?exLHy}9_dE4pz17oL(~E`{a`E-no7?`5)pDEpNY(-6VaJ?C^<J9(GN!A;n`PTPDZBE;WN>5k=ams`uyy<xmZYd@Og|04{1U(*1PGLR>h3WX?aZWQf~69?j-FsmL^GvInrgidoM2}r1u&}XB+q}oGg-NR#n^X*4uqBy?1qY$4<jzMBhXA);zPfx3*xU!VW$#fFa&MCOfRHVn0%6k8aaRw9dY?)7!uP!nGHEb#k+JxY|2h>kX{N{%!`IfvPX|S@e!nA3Iy~#cKVr)%cFx{mYSGj9h1H_Q6edkhuGk)3Z9gWp`~mJzG74m7(!J^o(!2de`mO?3IDzcV;$RQ`@foiYHlj%{3;+>#iT|K>v-`YH)PTx#fRu(|@AsKT#P^)cna!|9sUyU-MtAxP}M>w|Cc1s4_KI9hlp2y|UAEJ$C2$4Oh6~@uj-!Y-5tEyI$Y%KECN4u6l<*?fcwR_fD^|+djDIJ5u!>A&1N9itm{<3o-un;-)89^#pIPd{VwyzH_1WOyqZ$H)k$XXD-xcUafgjb=N#i!+Onn-Tj-cEob+(!(BOWa>FtC;21DH{%^IHo=c%;r;jstN15qS_U^F=Ab$c5Oh5W?fY!%^vdXfE>5Yf!rHF^<aF`B*be*L=(CF(%-E<?)%b0$BJ)|f2ZjG%ISw+Z8XcC`j+)bpk<79YXWEkdaV7mwG_kiObaNYym&C&ix(EpA7N#?}|aRxAsRm;!2e%e)a4AvZnHUPvwCa?b&OiHoo"
]

OUT_DIR = "extracted_artifacts"
os.makedirs(OUT_DIR, exist_ok=True)

def try_marshal_load(b):
    try:
        obj = marshal.loads(b)
        return obj
    except Exception:
        return None

def write_pyc_from_codeobj(code_obj, outpath):
    with open(outpath, "wb") as fh:
        fh.write(importlib.util.MAGIC_NUMBER)
        fh.write(struct.pack("I", int(time.time())))
        fh.write(struct.pack("I", 0))
        # write the code object using marshal.dump (not dumps)
        marshal.dump(code_obj, fh)
    print("WROTE .pyc ->", outpath)

def attempt_decode_chain(candidate_bytes, label):
    """
    Try a series of decoding attempts on candidate_bytes and look for a marshal.loads result.
    Returns list of successful tuples (desc, result_bytes_or_codeobj)
    """
    success = []
    def save_bytes(prefix, data):
        path = os.path.join(OUT_DIR, f"{prefix}.bin")
        with open(path, "wb") as fh:
            fh.write(data)
        print(" saved:", path)
        return path

    # 1) raw: try marshal.loads directly
    code_obj = try_marshal_load(candidate_bytes)
    if isinstance(code_obj, CodeType):
        print(f"[{label}] direct marshal.loads -> code object")
        outpath = os.path.join(OUT_DIR, f"{label}_direct_codeobj.pyc")
        write_pyc_from_codeobj(code_obj, outpath)
        success.append(("marshal->codeobj (direct)", code_obj))
        return success

    # 2) try zlib.decompress
    try:
        dec = zlib.decompress(candidate_bytes)
        print(f"[{label}] zlib.decompress succeeded ({len(dec)} bytes)")
        save_bytes(f"{label}_zlib", dec)
        co = try_marshal_load(dec)
        if isinstance(co, CodeType):
            print(f"[{label}] zlib -> marshal.loads -> code object")
            outpath = os.path.join(OUT_DIR, f"{label}_zlib_codeobj.pyc")
            write_pyc_from_codeobj(co, outpath)
            success.append(("zlib -> marshal -> codeobj", co))
    except Exception:
        pass

    # 3) base85/ascii85/b85 - many CTFs use base85 (b85decode / a85decode)
    for name, func in (("b85", base64.b85decode), ("a85", base64.a85decode), ("b64", base64.b64decode)):
        try:
            decoded = func(candidate_bytes)
            print(f"[{label}] {name} decode succeeded ({len(decoded)} bytes)")
            save_bytes(f"{label}_{name}", decoded)
            # try zlib after base decode
            try:
                dec2 = zlib.decompress(decoded)
                print(f"  -> {name} -> zlib succeeded ({len(dec2)} bytes)")
                save_bytes(f"{label}_{name}_zlib", dec2)
                co = try_marshal_load(dec2)
                if isinstance(co, CodeType):
                    print(f"  -> {name} -> zlib -> marshal.loads -> code object")
                    outpath = os.path.join(OUT_DIR, f"{label}_{name}_zlib_codeobj.pyc")
                    write_pyc_from_codeobj(co, outpath)
                    success.append((f"{name} -> zlib -> marshal -> codeobj", co))
            except Exception:
                # maybe direct marshal
                co = try_marshal_load(decoded)
                if isinstance(co, CodeType):
                    print(f"  -> {name} -> marshal.loads -> code object")
                    outpath = os.path.join(OUT_DIR, f"{label}_{name}_codeobj.pyc")
                    write_pyc_from_codeobj(co, outpath)
                    success.append((f"{name} -> marshal -> codeobj", co))
        except Exception:
            continue

    # 4) try ascii printable decode: if candidate is str, try encode('utf-8')
    # Already handling bytes vs str at caller.

    return success

def collect_candidates_from_codeobj(code_obj):
    """Walk codeobj.consts recursively to collect large bytes/strings"""
    found = []
    seen = set()
    def walk(c):
        if id(c) in seen:
            return
        seen.add(id(c))
        if isinstance(c, (bytes, bytearray)):
            if len(c) >= 64:  # heuristic threshold
                found.append((repr(c[:40])+"...", c))
        elif isinstance(c, str):
            if len(c) >= 64:
                found.append((c[:40]+"...", c.encode('utf-8', errors='ignore')))
        elif isinstance(c, CodeType):
            for cc in c.co_consts:
                walk(cc)
        elif isinstance(c, (tuple, list)):
            for el in c:
                walk(el)
    walk(code_obj)
    return found

def main():
    global sequencer_marshal_bytes, encrypted_sequencer_data
    if encrypted_sequencer_data and sequencer_marshal_bytes:
        print("Both top-level zlib blob and raw marshal present. Using raw marshal bytes.")
    if encrypted_sequencer_data and not sequencer_marshal_bytes:
        print("Decompressing encrypted_sequencer_data...")
        try:
            sequencer_marshal_bytes = zlib.decompress(encrypted_sequencer_data)
            print("Decompression OK: got", len(sequencer_marshal_bytes), "bytes (marshal?)")
        except Exception as e:
            print("zlib.decompress failed:", e)
            # fall back to scanning fallback_candidates
            sequencer_marshal_bytes = None

    if sequencer_marshal_bytes:
        top_obj = try_marshal_load(sequencer_marshal_bytes)
        if isinstance(top_obj, CodeType):
            print("Top-level marshal.loads -> CodeType object. Scanning its constants...")
            candidates = collect_candidates_from_codeobj(top_obj)
            if not candidates:
                print("No large bytes/strings found in constants; saving raw marshal bytes to file.")
                with open(os.path.join(OUT_DIR, "sequencer_raw_marshal.bin"), "wb") as fh:
                    fh.write(sequencer_marshal_bytes)
                print("Saved raw marshal bytes for manual inspection.")
            else:
                print(f"Found {len(candidates)} large constants - attempting decode chains...")
                for idx, (label_prefix, cb) in enumerate(candidates):
                    label = f"const_{idx}"
                    # cb might be str bytes; ensure bytes
                    cand_bytes = cb if isinstance(cb, (bytes, bytearray)) else str(cb).encode("utf-8", errors="ignore")
                    attempt_decode_chain(cand_bytes, label)
        else:
            print("Top-level marshal.loads did not return a code object. It returned:", type(top_obj))
            # maybe top_obj is a tuple/list containing code object or the constants directly
            # scan it for bytes/strings
            print("Scanning the top-level object for large bytes/strings...")
            def scan_obj(o):
                found = []
                if isinstance(o, (bytes, bytearray)):
                    if len(o) >= 64:
                        found.append(o)
                elif isinstance(o, str):
                    if len(o) >= 64:
                        found.append(o.encode("utf-8", errors="ignore"))
                elif isinstance(o, (tuple, list)):
                    for el in o:
                        found.extend(scan_obj(el))
                return found
            bigs = scan_obj(top_obj)
            if bigs:
                print("Found", len(bigs), "candidates in top-level object. Trying decode chains...")
                for i, b in enumerate(bigs):
                    attempt_decode_chain(b, f"top_{i}")
            else:
                print("No large candidates found in top-level object. Falling back to fallback_candidates.")
                for i, fb in enumerate(fallback_candidates):
                    bb = fb if isinstance(fb, (bytes, bytearray)) else str(fb).encode("utf-8", errors="ignore")
                    attempt_decode_chain(bb, f"fallback_{i}")

    else:
        # no marshal bytes; use fallback candidates
        if not fallback_candidates:
            print("No input provided. Set encrypted_sequencer_data or sequencer_marshal_bytes or fallback_candidates.")
            sys.exit(1)
        print("No top-level marshal bytes; trying fallback_candidates...")
        for i, fb in enumerate(fallback_candidates):
            bb = fb if isinstance(fb, (bytes, bytearray)) else str(fb).encode("utf-8", errors="ignore")
            attempt_decode_chain(bb, f"fallback_{i}")

    print("\nDone. Check the folder:", OUT_DIR)
    print("If any '.pyc' files were written, run:")
    print("   decompyle3 <that_pyc> > recovered_source.py")
    print("or: decompyle3 sequencer_recovered.pyc > sequencer.py")

if __name__ == "__main__":
    main()
