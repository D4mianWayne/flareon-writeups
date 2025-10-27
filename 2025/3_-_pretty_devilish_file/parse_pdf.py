import zlib

# Path to your PDF
pdf_path = "pretty_devilish_file.pdf"

with open(pdf_path, "rb") as f:
    pdf_bytes = f.read()

# Function to find all FlateDecode streams
def extract_flate_streams(pdf_bytes):
    stream = pdf_bytes.find(b"stream") + 8
    endstream = pdf_bytes.find(b"endstream") - 2
    print(pdf_bytes[stream:endstream])
    compressed_data = pdf_bytes[stream:endstream]
    print("Attempting Raw Deflate Decompression...")

    try:
        # wbits=-15 tells zlib to treat the data as raw Deflate, skipping header/footer checks.
        decompressed_content = zlib.decompress(compressed_data, wbits=-15) 
        
        # Decode the bytes to a readable string (PDF content streams often use Latin-1 or ASCII)
        print("--- Decompressed Content Stream ---")
        print(decompressed_content.decode('latin1')) 
        print("-----------------------------------")
        
    except zlib.error as e:
        print(f"Still failed to decompress: {e}")

print(extract_flate_streams(pdf_bytes))