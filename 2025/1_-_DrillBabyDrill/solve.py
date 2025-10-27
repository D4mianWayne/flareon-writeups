#!/usr/bin/env python3
# bruteforce_flag.py
# Brute-force key (0..255) for the provided XOR-based decoder.

encoded = b"\xd0\xc7\xdf\xdb\xd4\xd0\xd4\xdc\xe3\xdb\xd1\xcd\x9f\xb5\xa7\xa7\xa0\xac\xa3\xb4\x88\xaf\xa6\xaa\xbe\xa8\xe3\xa0\xbe\xff\xb1\xbc\xb9"

def decode_with_key(key: int, data: bytes) -> str:
    # replicate: plaintext.append(chr(ord(encoded[i]) ^ (key+i)))
    out_chars = []
    for i, b in enumerate(data):
        val = b ^ ((key + i) & 0xFF)
        out_chars.append(chr(val))
    return ''.join(out_chars)

def is_printable(s: str) -> bool:
    # consider basic printable ASCII (space .. ~)
    return all(32 <= ord(ch) <= 126 for ch in s)

def main():
    printable_results = []
    all_results_file = "bruteforce_all_results.txt"

    with open(all_results_file, "w", encoding="utf-8", errors="replace") as fh:
        for key in range(256):
            plain = decode_with_key(key, encoded)
            # write a safe representation to the file
            fh.write(f"key={key:3d}: {repr(plain)}\n")

            if is_printable(plain):
                printable_results.append((key, plain))

    # show printable candidates on stdout
    if printable_results:
        print("Printable candidate plaintexts (likely human-readable):")
        for k, p in printable_results:
            print(f"key={k:3d}: {p}")
    else:
        print("No fully printable ASCII candidates found. See", all_results_file, "for all outputs (escaped).")

    print(f"All 256 outputs were saved to: {all_results_file}")

if __name__ == "__main__":
    main()
