"""Week 3 studio — the ECB penguin (README bonus, for the Task 1 demo).

Encrypts a flat-shaded penguin bitmap with the SAME cipher and the SAME key
under two modes and renders both. Run: python3 penguin.py
Writes results/penguin.png
"""
import os

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from modes import BS, ecb_encrypt, cbc_encrypt, distinct_blocks

W = H = 96


def penguin():
    """Flat-shaded penguin: few distinct byte values, so ECB has structure to leak."""
    img = np.full((H, W), 235, np.uint8)
    y, x = np.mgrid[0:H, 0:W]

    body = ((x - 48) / 30.0) ** 2 + ((y - 55) / 40.0) ** 2 <= 1
    head = ((x - 48) / 20.0) ** 2 + ((y - 25) / 20.0) ** 2 <= 1
    img[body | head] = 20

    belly = ((x - 48) / 20.0) ** 2 + ((y - 60) / 30.0) ** 2 <= 1
    face = ((x - 48) / 14.0) ** 2 + ((y - 29) / 14.0) ** 2 <= 1
    img[belly | face] = 235

    for cx in (41, 55):
        img[((x - cx) / 3.0) ** 2 + ((y - 24) / 3.0) ** 2 <= 1] = 20
    img[((x - 48) / 5.0) ** 2 + ((y - 34) / 3.5) ** 2 <= 1] = 150
    for cx in (38, 58):
        img[((x - cx) / 9.0) ** 2 + ((y - 93) / 4.0) ** 2 <= 1] = 150
    return img


def as_image(data):
    return np.frombuffer(data[:W * H], np.uint8).reshape(H, W)


if __name__ == "__main__":
    plain = penguin()
    raw = plain.tobytes()
    key = os.urandom(16)

    ecb, cbc = ecb_encrypt(raw, key), cbc_encrypt(raw, key, os.urandom(BS))
    total = len(raw) // BS
    panels = [("plaintext", plain, distinct_blocks(raw)),
              ("ECB — same cipher, same key", as_image(ecb), distinct_blocks(ecb)),
              ("CBC — same cipher, same key", as_image(cbc), distinct_blocks(cbc))]

    fig, axes = plt.subplots(1, 3, figsize=(11, 4.2))
    for ax, (title, im, d) in zip(axes, panels):
        ax.imshow(im, cmap="gray", vmin=0, vmax=255, interpolation="nearest")
        ax.set_title(f"{title}\n{d}/{total} distinct blocks", fontsize=10)
        ax.axis("off")
    fig.suptitle("The mode decided whether the data leaked, not the cipher",
                 fontsize=12, y=0.99)
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    os.makedirs("results", exist_ok=True)
    fig.savefig("results/penguin.png", dpi=140)

    for title, _, d in panels:
        print(f"{title:<32} {d:>5}/{total} distinct blocks")
    print("\nwrote results/penguin.png")
