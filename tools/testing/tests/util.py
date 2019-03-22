import math


def shannon_entropy(data):
    sum = 0.0
    total = len(data)
    for x in range(0, 256):
        freq = data.count(x)
        p = freq / total
        if p > 0:
            sum -= p * math.log2(p)
    return sum
