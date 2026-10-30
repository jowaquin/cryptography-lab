# Experiment 3: ECB vs CBC on a Picture
# "Prove It or Break It" series, Part 1 - Joaquin Thiogo

from pathlib import Path

from PIL import Image, ImageDraw
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# fixed key (demo only)
key: bytes = b"0123456789abcdef"

size = 256
blue = (30, 60, 120)
white = (255, 255, 255)

# draw a padlock with flat colors
image = Image.new("RGB", (size, size), white)
draw = ImageDraw.Draw(image)
draw.arc((68, 28, 188, 148), start=180, end=360,
         fill=blue, width=22)  # shackle
draw.rectangle((68, 88, 78, 118), fill=blue)  # left leg of the shackle
draw.rectangle((178, 88, 188, 118), fill=blue)  # right leg of the shackle
draw.rounded_rectangle((48, 118, 208, 228), radius=14, fill=blue)  # body
draw.ellipse((114, 148, 142, 176), fill=white)  # keyhole (round part)
draw.rectangle((122, 168, 134, 204), fill=white)  # keyhole (slot)

# the raw pixel bytes
plaintext = image.tobytes()

# encrypt the same bytes with ECB and with CBC (random IV)
ecb_ciphertext = AES.new(key, AES.MODE_ECB).encrypt(plaintext)
iv = get_random_bytes(16)
cbc_ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)


def unique_blocks(data: bytes) -> int:
    # count how many different 16-byte blocks the data contains
    blocks = set()
    for i in range(0, len(data), 16):
        blocks.add(data[i:i + 16])
    return len(blocks)


total = len(plaintext) // 16
print(f"Total blocks        : {total}")
print(f"Unique in plaintext : {unique_blocks(plaintext)}")
print(f"Unique in ECB       : {unique_blocks(ecb_ciphertext)}")
print(f"Unique in CBC       : {unique_blocks(cbc_ciphertext)}")

# turn the encrypted bytes back into pictures
ecb_image = Image.frombytes("RGB", (size, size), ecb_ciphertext)
cbc_image = Image.frombytes("RGB", (size, size), cbc_ciphertext)

# put original, ECB and CBC side by side in one picture
canvas = Image.new("RGB", (size * 3 + 40, size), white)
canvas.paste(image, (0, 0))
canvas.paste(ecb_image, (size + 20, 0))
canvas.paste(cbc_image, (size * 2 + 40, 0))
canvas.save(Path(__file__).parent / "padlock_ecb_vs_cbc.png")
