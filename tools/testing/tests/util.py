import math


def shannon_entropy(data):
    s = 0.0
    total = len(data)
    for x in range(0, 256):
        freq = data.count(x)
        p = freq / total
        if p > 0:
            s -= p * math.log2(p)
    return s
