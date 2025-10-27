#!/usr/bin/env python3

import binascii
from PIL import Image
import io

def extract_pixel_data_pil():
    """
    Extract pixel data using PIL (Pillow)
    """
    # Your JPEG hex data
    hex_data = "ffd8ffe000104a46494600010100000100010000ffdb0043000101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101ffc0000b080001002501011100ffc40017000100030000000000000000000000000006040708ffc400241000000209050100000000000000000000000702050608353776b6b7030436747577ffda0008010100003f00c54d3401dcbbfb9c38db8a7dd265a2159e9d945a086407383aabd52e5034c274e57179ef3bcdfca50f0af80aff00e986c64568c7ffd9"
    
    # Convert hex to bytes
    jpeg_bytes = binascii.unhexlify(hex_data)
    
    try:
        # Load image from bytes
        image = Image.open(io.BytesIO(jpeg_bytes))
        
        print("Image Information:")
        print(f"  Size: {image.size}")
        print(f"  Mode: {image.mode}")
        print(f"  Format: {image.format}")
        
        # Get pixel data
        pixels = list(image.getdata())
        
        print(f"\nPixel Data ({len(pixels)} pixels):")
        print("=" * 40)
        
        # Method 1: Show all pixel values
        for i, pixel in enumerate(pixels):
            if image.mode == 'RGB':
                r, g, b = pixel
                print(f"  Pixel {i:2d}: RGB({r:3d}, {g:3d}, {b:3d}) | Hex: #{r:02x}{g:02x}{b:02x}")
                
                # Try interpreting RGB values as ASCII
                ascii_chars = ""
                for val in [r, g, b]:
                    if 32 <= val <= 126:
                        ascii_chars += chr(val)
                    else:
                        ascii_chars += "."
                if ascii_chars.strip("."):
                    print(f"           ASCII attempt: '{ascii_chars}'")
                    
            elif image.mode == 'L':  # Grayscale
                print(f"  Pixel {i:2d}: Gray({pixel:3d}) | Hex: {pixel:02x}")
                if 32 <= pixel <= 126:
                    print(f"           ASCII: '{chr(pixel)}'")
            else:
                print(f"  Pixel {i:2d}: {pixel}")
        
        # Method 2: Try to extract flag from pixel values
        print(f"\nFlag Extraction Attempts:")
        print("=" * 40)
        
        # Attempt 1: Concatenate all RGB values as ASCII
        flag_attempt1 = ""
        for pixel in pixels:
            if image.mode == 'RGB':
                r, g, b = pixel
                for val in [r, g, b]:
                    if 32 <= val <= 126:
                        flag_attempt1 += chr(val)
            elif image.mode == 'L':
                if 32 <= pixel <= 126:
                    flag_attempt1 += chr(pixel)
        
        print(f"Method 1 (All RGB as ASCII): '{flag_attempt1}'")
        
        # Attempt 2: Only use R channel
        if image.mode == 'RGB':
            flag_attempt2 = ""
            for pixel in pixels:
                r, g, b = pixel
                if 32 <= r <= 126:
                    flag_attempt2 += chr(r)
            print(f"Method 2 (R channel only): '{flag_attempt2}'")
            
            # Attempt 3: Only use G channel
            flag_attempt3 = ""
            for pixel in pixels:
                r, g, b = pixel
                if 32 <= g <= 126:
                    flag_attempt3 += chr(g)
            print(f"Method 3 (G channel only): '{flag_attempt3}'")
            
            # Attempt 4: Only use B channel
            flag_attempt4 = ""
            for pixel in pixels:
                r, g, b = pixel
                if 32 <= b <= 126:
                    flag_attempt4 += chr(b)
            print(f"Method 4 (B channel only): '{flag_attempt4}'")
        
        # Attempt 5: Treat pixel values as hex digits
        hex_from_pixels = ""
        for pixel in pixels:
            if image.mode == 'RGB':
                r, g, b = pixel
                hex_from_pixels += f"{r:02x}{g:02x}{b:02x}"
            elif image.mode == 'L':
                hex_from_pixels += f"{pixel:02x}"
        
        print(f"Method 5 (Pixels as hex): {hex_from_pixels}")
        
        # Try to decode the hex as ASCII
        try:
            hex_decoded = binascii.unhexlify(hex_from_pixels)
            ascii_from_hex = hex_decoded.decode('ascii', errors='ignore')
            if ascii_from_hex.strip():
                print(f"  Hex decoded to ASCII: '{ascii_from_hex}'")
        except:
            pass
        
        # Save enlarged version for visual inspection
        if image.size[0] < 100 or image.size[1] < 100:
            enlarged = image.resize((image.size[0] * 20, image.size[1] * 20), Image.NEAREST)
            enlarged.save("enlarged_flag.png")
            print(f"\nEnlarged image saved as: enlarged_flag.png")
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False

def manual_pixel_extraction():
    """
    Manual pixel extraction by parsing JPEG structure
    """
    print("\n" + "=" * 50)
    print("MANUAL EXTRACTION (if PIL fails):")
    print("=" * 50)
    
    print("If PIL fails, you can use these tools:")
    print("1. ImageMagick: convert flag.jpg -depth 8 txt:- | grep -v '#'")
    print("2. Python OpenCV: cv2.imread('flag.jpg')")
    print("3. ffmpeg: ffmpeg -i flag.jpg -f rawvideo -pix_fmt rgb24 pixels.raw")
    print("4. Online JPEG decoder tools")
    print("5. Hex editor to manually parse JPEG scan data")

if __name__ == "__main__":
    print("JPEG Pixel Data Extractor")
    print("=" * 50)
    
    success = extract_pixel_data_pil()
    
    if not success:
        manual_pixel_extraction()
    
    print(f"\nAdditional Tips:")
    print("- Look for patterns in the RGB values")
    print("- Check if pixel values form ASCII characters")
    print("- Try XORing consecutive pixels")
    print("- Look for LSB steganography patterns")