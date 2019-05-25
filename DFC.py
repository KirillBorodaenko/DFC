## Disclaimer
# The realization of decorrelated fast cipher (DFC) is reserved.
# Author: Kirill Borodaenko
# Date: 05.21.2019

# import libs
import random as rnd
from math import*

## encoder function
# param in: text message
# param out: bit sequence :: 128
def encode_msg(text, encoding = 'UTF-8'):
    bits = bin(int.from_bytes(text.encode(encoding), 'little'))[2:]
    k = 0
    while (128 * k < len(bits)):
        k += 1
    return bits.zfill(128 * k)

## decoder function
# param in: bit sequence :: 128
# param out: text message
def decode_msg(bits, encoding = 'UTF-8'):
    n = int(bits, 2)
    return n.to_bytes(n.bit_length(), 'little').decode(encoding) or '\0'

## slicing message on 128-bit parts
# param in: full message
# param out: sliced message
def slicer(message):
    sliced_message = []
    k = 0
    while (k != len(message) / 128):
        right_part = k * 128
        left_part = (k + 1) * 128
        sliced_message.append(message[right_part:left_part])
        k += 1
    return sliced_message

# hex constants
KC = 0xeb64749a
KD = 0x86d1bf275b9b241d

# RT tab
RT = [0xb7e15162, 0x8aed2a6a, 0xbf715880, 0x9cf4f3c7, 0x62e7160f, 0x38b4da56, 0xa784d904, 0x5190cfef, 0x324e7738, 0x926cfbe5,
      0xf4bf8d8d, 0x8c31d763, 0xda06c80a, 0xbb1185eb, 0x4f7c7b57, 0x57f59594, 0x90cfd47d, 0x7c19bb42, 0x158d9554, 0xf7b46bce,
      0xd55c4d79, 0xfd5f24d6, 0x613c31c3, 0x839a2ddf, 0x8a9a276b, 0xcfbfa1c8, 0x77c56284, 0xdab79cd4, 0xc2d3293d, 0x20e9e5ea,
      0xf02ac60a, 0xcc93ed87, 0x4422a52e, 0xcb238fee, 0xe5ab6add, 0x835fd1a0, 0x753d0a8f, 0x78e537d2, 0xb95bb79d, 0x8dcaec64,
      0x2c1e9f23, 0xb829b5c2, 0x780bf387, 0x37df8bb3, 0x00d01334, 0xa0d0bd86, 0x45cbfa73, 0xa6160ffe, 0x393c48cb, 0xbbca060f,
      0x0ff8ec6d, 0x31beb5cc, 0xeed7f2f0, 0xbb088017, 0x163bc60d, 0xf45a0ecb, 0x1bcd289b, 0x06cbbfea, 0x21ad08e1, 0x847f3f73,
      0x78d56ced, 0x94640d6e, 0xf0d3d37b, 0xe6700831]

# constant 2^64
const_2_64_str = str(10000000000000000000000000000000000000000000000000000000000000000)
const_2_64_int = int(const_2_64_str, 2)

## round function DFC
# params in: round key, 64-bit source subblock
# param out: 64-bit ciphered subblock
def dfc_round_func(round_key, source_subblock):
    # key slicing
    round_key_str = bin(round_key)[2:].zfill(128)
    a_str = round_key_str[0:64]
    b_str = round_key_str[64:128]
    a = int(a_str, 2)
    b = int(b_str, 2)

    # intermediate value calculation
    x = (((~a * ~source_subblock) + ~b) % (const_2_64_int + 13)) % const_2_64_int

    # x slicing
    x_str = bin(x)[2:].zfill(64)
    x1_str = x_str[0:32]
    x2_str = x_str[32:64]
    x1 = int(x1_str, 2)
    x2 = int(x2_str, 2)

    # trunc set-up
    num_str = x1_str[0:6]
    num = int(num_str, 2)

    # calculation
    part_1_str = bin(x2 ^ RT[~num])[2:].zfill(32)
    part_2_str = bin(x1 ^ KC)[2:].zfill(32)
    concatenacio_str = part_1_str + part_2_str
    concatenacio_int = int(concatenacio_str, 2)
    ciphered_subblock = (~concatenacio_int + ~KD) % const_2_64_int

    return ciphered_subblock

## block-scheme of algorythm
# param in: 128-bit source block
# param out: 128-bit ciphered block
def struct_algo_dfc(source_block_str):
    
    # block slicing 
    left_subblock_str = source_block_str[0:64]
    right_subblock_str = source_block_str[64:128]
    left_subblock = int(left_subblock_str, 2)
    right_subblock = int(right_subblock_str, 2)
    
    # 8 rounds
    k = 0
    while (k != 8):
        round_calc = dfc_round_func(cipher_key, right_subblock)
        helper = right_subblock
        right_subblock = round_calc ^ left_subblock
        left_subblock = helper
        k += 1

    # form ciphered block
    left_subblock_str = bin(left_subblock)[2:].zfill(64)
    rigth_subblock_str = bin(right_subblock)[2:].zfill(64)
    ciphered_block_str = rigth_subblock_str + left_subblock_str
    
    return ciphered_block_str.zfill(128)

## cipherer
# param in: sliced message
# param out: ciphered message
def cipherer(sliced_message):

    ciphered_message = ''
    i = 0
    while (i != len(sliced_message)):
        ciphered_message += struct_algo_dfc(sliced_message[i])
        i += 1
        
    return ciphered_message

## main demo
# param in: none
# param out: none
istream = open('source_message.txt')
source_message = encode_msg(istream.read())
print("Source message:", decode_msg(source_message), '\n')
print("Encoded message:", source_message)
print("Size:", len(source_message), '\n')
cipher_key = rnd.getrandbits(128)

sliced_message = slicer(source_message)
ciphered_message = cipherer(sliced_message)
print("Ciphered message:", ciphered_message)
print("Size:", len(source_message), '\n')

sliced_message = slicer(ciphered_message)
deciphered_message = cipherer(sliced_message)
print("Deciphered message:", deciphered_message)
print("Size:", len(source_message), '\n')

print("Decoded message:", decode_msg(deciphered_message))

