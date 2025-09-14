#!/usr/bin/env python3
"""
steg.py - simple LSB audio steganography for WAV (encode/decode)
Supports 8-bit (unsigned) and 16-bit (signed) PCM WAV files.
Optional encryption with cryptography.Fernet (install cryptography).
"""

import wave
import argparse
import numpy as np
import os
import sys

# optional crypto
try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False

def capacity_bytes(n_frames, n_channels):
    total_samples = n_frames * n_channels
    # reserve 32 bits for length header
    return max((total_samples - 32) // 8, 0)

def read_wav_as_samples(path):
    wf = wave.open(path, 'rb')
    params = wf.getparams()
    n_channels, sampwidth, framerate, n_frames = params.nchannels, params.sampwidth, params.framerate, params.nframes
    frames = wf.readframes(n_frames)
    wf.close()

    if sampwidth == 2:
        dtype = '<i2'  # little-endian 16-bit signed
    elif sampwidth == 1:
        dtype = 'u1'   # unsigned 8-bit
    else:
        raise ValueError("Only 8-bit or 16-bit PCM WAV supported. sampwidth: {}".format(sampwidth))

    samples = np.frombuffer(frames, dtype=dtype).copy()
    return samples, n_channels, sampwidth, framerate, n_frames

def write_samples_to_wav(path, samples, n_channels, sampwidth, framerate):
    wf = wave.open(path, 'wb')
    wf.setnchannels(n_channels)
    wf.setsampwidth(sampwidth)
    wf.setframerate(framerate)
    wf.writeframes(samples.tobytes())
    wf.close()

def bytes_to_bitstr(b):
    return ''.join(f'{byte:08b}' for byte in b)

def bitstr_to_bytes(bs):
    b = bytearray()
    for i in range(0, len(bs), 8):
        byte = bs[i:i+8]
        if len(byte) < 8:
            break
        b.append(int(byte, 2))
    return bytes(b)

def embed(cover_wav, out_wav, secret_bytes, encrypt=False, key=None):
    if encrypt:
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography not available, install `cryptography` to use encryption.")
        if key is None:
            # generate a key and print it
            key = Fernet.generate_key()
            print("[+] Generated key (save this):", key.decode())
        elif isinstance(key, str):
            key = key.encode()
        f = Fernet(key)
        secret_bytes = f.encrypt(secret_bytes)

    samples, n_channels, sampwidth, framerate, n_frames = read_wav_as_samples(cover_wav)
    total_capacity = capacity_bytes(n_frames, n_channels)
    msg_len = len(secret_bytes)
    if msg_len == 0:
        raise ValueError("Secret is empty.")
    if msg_len > total_capacity:
        raise ValueError(f"Not enough capacity: capacity {total_capacity} bytes, secret {msg_len} bytes.")

    # build bitstring with 32-bit length header (message length in bytes)
    len_bits = f'{msg_len:032b}'
    msg_bits = bytes_to_bitstr(secret_bytes)
    bits = len_bits + msg_bits
    total_bits = len(bits)
    total_samples = n_frames * n_channels

    # ensure samples is 1D array of integers
    # modify LSB of first total_bits samples
    for i in range(total_bits):
        bit = int(bits[i])
        # clear LSB and set to bit
        samples[i] = (samples[i] & ~1) | bit

    write_samples_to_wav(out_wav, samples, n_channels, sampwidth, framerate)
    print(f"[+] Embedded {msg_len} bytes -> {out_wav} (capacity {total_capacity} bytes)")

def extract(stego_wav, out_file=None, decrypt=False, key=None):
    samples, n_channels, sampwidth, framerate, n_frames = read_wav_as_samples(stego_wav)
    total_samples = n_frames * n_channels

    # read first 32 bits for length
    if total_samples < 32:
        raise ValueError("Audio too short or not valid for extraction.")
    len_bits = ''.join(str(int(samples[i] & 1)) for i in range(32))
    msg_len = int(len_bits, 2)
    total_msg_bits = msg_len * 8
    if 32 + total_msg_bits > total_samples:
        raise ValueError("Corrupt or incomplete message (length mismatch).")

    msg_bits = ''.join(str(int(samples[i] & 1)) for i in range(32, 32 + total_msg_bits))
    secret = bitstr_to_bytes(msg_bits)

    if decrypt:
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography not available, install `cryptography` to use encryption.")
        if key is None:
            raise ValueError("Decryption requested but no key provided.")
        if isinstance(key, str):
            key = key.encode()
        f = Fernet(key)
        secret = f.decrypt(secret)

    if out_file:
        # write as binary
        with open(out_file, 'wb') as fh:
            fh.write(secret)
        print(f"[+] Extracted {len(secret)} bytes to {out_file}")
    else:
        # print as text if decodable, else show hex
        try:
            text = secret.decode('utf-8')
            print("[+] Extracted message (utf-8):")
            print(text)
        except Exception:
            print("[+] Extracted binary (hex):")
            print(secret.hex()[:200] + ('...' if len(secret) > 100 else ''))

def main():
    p = argparse.ArgumentParser(description="Simple LSB audio steganography (WAV)")
    sub = p.add_subparsers(dest='cmd')

    enc = sub.add_parser('encode', help='Embed secret into WAV')
    enc.add_argument('-c','--cover', required=True, help='cover WAV path (PCM 8/16-bit)')
    enc.add_argument('-s','--secret', required=True, help='secret file path (text or binary)')
    enc.add_argument('-o','--out', default='stego.wav', help='output WAV path')
    enc.add_argument('--encrypt', action='store_true', help='encrypt secret (Fernet)')
    enc.add_argument('--key', default=None, help='Fernet key (base64) or key file path')

    dec = sub.add_parser('decode', help='Extract secret from WAV')
    dec.add_argument('-i','--input', required=True, help='stego WAV path')
    dec.add_argument('-o','--out', default=None, help='output file path to save secret (if omitted prints)')
    dec.add_argument('--decrypt', action='store_true', help='decrypt using Fernet')
    dec.add_argument('--key', default=None, help='Fernet key (base64) or key file path')

    args = p.parse_args()
    if args.cmd == 'encode':
        if not os.path.exists(args.cover):
            print("Cover file not found:", args.cover); sys.exit(1)
        if not os.path.exists(args.secret):
            print("Secret file not found:", args.secret); sys.exit(1)
        # read secret bytes
        with open(args.secret, 'rb') as fh:
            secret_bytes = fh.read()
        key = None
        if args.key:
            if os.path.exists(args.key):
                key = open(args.key,'rb').read().strip()
            else:
                key = args.key
        embed(args.cover, args.out, secret_bytes, encrypt=args.encrypt, key=key)
    elif args.cmd == 'decode':
        if not os.path.exists(args.input):
            print("Input file not found:", args.input); sys.exit(1)
        key = None
        if args.key:
            if os.path.exists(args.key):
                key = open(args.key,'rb').read().strip()
            else:
                key = args.key
        extract(args.input, out_file=args.out, decrypt=args.decrypt, key=key)
    else:
        p.print_help()

if __name__ == '__main__':
    main()
