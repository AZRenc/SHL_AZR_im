import heapq


class _ShlNode:
    __slots__ = ('shl_freq', 'shl_byte', 'shl_left', 'shl_right')

    def __init__(self, shl_freq, shl_byte=None, shl_left=None, shl_right=None):
        self.shl_freq = shl_freq
        self.shl_byte = shl_byte
        self.shl_left = shl_left
        self.shl_right = shl_right


def _shl_build(shl_freqs):
    shl_heap = []
    shl_tie = 0
    for shl_b, shl_f in enumerate(shl_freqs):
        if shl_f > 0:
            heapq.heappush(shl_heap, (shl_f, shl_tie, _ShlNode(shl_f, shl_b)))
            shl_tie += 1
    if not shl_heap:
        return None
    while len(shl_heap) > 1:
        shl_f1, _, shl_n1 = heapq.heappop(shl_heap)
        shl_f2, _, shl_n2 = heapq.heappop(shl_heap)
        shl_merged = _ShlNode(shl_f1 + shl_f2, shl_left=shl_n1, shl_right=shl_n2)
        heapq.heappush(shl_heap, (shl_merged.shl_freq, shl_tie, shl_merged))
        shl_tie += 1
    return shl_heap[0][2]


def _shl_codes(shl_node, shl_prefix=0, shl_len=0):
    shl_codes = {}
    if shl_node.shl_byte is not None:
        shl_codes[shl_node.shl_byte] = (shl_prefix, shl_len if shl_len > 0 else 1)
    else:
        if shl_node.shl_left:
            shl_codes.update(_shl_codes(shl_node.shl_left, shl_prefix << 1, shl_len + 1))
        if shl_node.shl_right:
            shl_codes.update(_shl_codes(shl_node.shl_right, (shl_prefix << 1) | 1, shl_len + 1))
    return shl_codes


def _shl_serialize(shl_node):
    if shl_node.shl_byte is not None:
        return b'\x01' + bytes([shl_node.shl_byte])
    return b'\x00' + _shl_serialize(shl_node.shl_left) + _shl_serialize(shl_node.shl_right)


def _shl_deserialize(shl_data, shl_pos=0):
    if shl_pos >= len(shl_data):
        raise ValueError('Invalid Huffman tree')
    if shl_data[shl_pos] == 1:
        if shl_pos + 1 >= len(shl_data):
            raise ValueError('Invalid Huffman tree')
        return _ShlNode(0, shl_data[shl_pos + 1]), shl_pos + 2
    shl_left, shl_pos = _shl_deserialize(shl_data, shl_pos + 1)
    shl_right, shl_pos = _shl_deserialize(shl_data, shl_pos)
    return _ShlNode(0, shl_left=shl_left, shl_right=shl_right), shl_pos


def shll_compress(shl_data):
    shl_freqs = [0] * 256
    for shl_b in shl_data:
        shl_freqs[shl_b] += 1
    shl_root = _shl_build(shl_freqs)
    if shl_root is None:
        return (0).to_bytes(2, 'big') + (0).to_bytes(4, 'big')
    shl_codes = _shl_codes(shl_root)
    shl_tree = _shl_serialize(shl_root)
    shl_buf = 0
    shl_count = 0
    shl_out = bytearray()
    for shl_b in shl_data:
        shl_code, shl_len = shl_codes[shl_b]
        for shl_i in range(shl_len - 1, -1, -1):
            shl_bit = (shl_code >> shl_i) & 1
            shl_buf = (shl_buf << 1) | shl_bit
            shl_count += 1
            if shl_count == 8:
                shl_out.append(shl_buf)
                shl_buf = 0
                shl_count = 0
    if shl_count > 0:
        shl_out.append(shl_buf << (8 - shl_count))
    return len(shl_tree).to_bytes(2, 'big') + len(shl_data).to_bytes(4, 'big') + shl_tree + bytes(shl_out)


def shll_decompress(shl_data):
    if len(shl_data) < 6:
        raise ValueError('Invalid data')
    shl_tree_len = int.from_bytes(shl_data[:2], 'big')
    shl_orig_len = int.from_bytes(shl_data[2:6], 'big')
    if shl_tree_len == 0 and shl_orig_len == 0:
        return b''
    if len(shl_data) < 6 + shl_tree_len:
        raise ValueError('Invalid data')
    shl_tree_bytes = shl_data[6:6 + shl_tree_len]
    shl_data_bytes = shl_data[6 + shl_tree_len:]
    shl_root, _ = _shl_deserialize(shl_tree_bytes, 0)
    if shl_orig_len == 0:
        return b''
    if shl_root.shl_byte is not None:
        return bytes([shl_root.shl_byte]) * shl_orig_len
    shl_result = bytearray()
    shl_node = shl_root
    for shl_byte in shl_data_bytes:
        for shl_bit_index in range(7, -1, -1):
            shl_node = shl_node.shl_right if ((shl_byte >> shl_bit_index) & 1) else shl_node.shl_left
            if shl_node is None:
                raise ValueError('Invalid Huffman stream')
            if shl_node.shl_byte is not None:
                shl_result.append(shl_node.shl_byte)
                if len(shl_result) == shl_orig_len:
                    return bytes(shl_result)
                shl_node = shl_root
    if len(shl_result) != shl_orig_len:
        raise ValueError('Truncated Huffman stream')
    return bytes(shl_result)


compress = shll_compress
decompress = shll_decompress
