_B91_ALPHABET = "".join(chr(i) for i in range(33, 127) if chr(i) not in {'"', "'", '\\'})
_B91_ENC = list(_B91_ALPHABET)
_B91_DEC = {c: i for i, c in enumerate(_B91_ENC)}


def shll_enc(data):
    shl_b = 0
    shl_n = 0
    shl_out = []
    for shl_byte in data:
        shl_b |= shl_byte << shl_n
        shl_n += 8
        if shl_n > 13:
            shl_v = shl_b & 8191
            if shl_v > 88:
                shl_b >>= 13
                shl_n -= 13
            else:
                shl_v = shl_b & 16383
                shl_b >>= 14
                shl_n -= 14
            shl_out.append(_B91_ENC[shl_v % 91])
            shl_out.append(_B91_ENC[shl_v // 91])
    if shl_n:
        shl_out.append(_B91_ENC[shl_b % 91])
        if shl_n > 7 or shl_b > 90:
            shl_out.append(_B91_ENC[shl_b // 91])
    return "".join(shl_out)


def shll_dec(shl_s):
    shl_v = -1
    shl_b = 0
    shl_n = 0
    shl_out = bytearray()
    for shl_ch in shl_s:
        if shl_ch not in _B91_DEC:
            continue
        shl_c = _B91_DEC[shl_ch]
        if shl_v < 0:
            shl_v = shl_c
        else:
            shl_v += shl_c * 91
            shl_b |= shl_v << shl_n
            if (shl_v & 8191) > 88:
                shl_n += 13
            else:
                shl_n += 14
            while shl_n >= 8:
                shl_out.append(shl_b & 255)
                shl_b >>= 8
                shl_n -= 8
            shl_v = -1
    if shl_v >= 0:
        shl_out.append((shl_b | (shl_v << shl_n)) & 255)
    return bytes(shl_out)


encode = shll_enc
decode = shll_dec
