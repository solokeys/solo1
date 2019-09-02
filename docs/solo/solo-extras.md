# Solo Extras

## Random number generation

Solo contains a True Random Number Generator (TRNG).  A TRNG is a hardware based mechanism
that leverages natural phenomenon to generate random numbers, which can be better than a traditional
RNG that has state and updates deterministically using cryptographic methods.

You can easily access the TRNG stream on Solo using our python tool [`solo-python`](https://github.com/solokeys/solo-python).

```
solo key rng raw > random.bin
```

Or you can seed the state of the RNG on your kernel (`/dev/random`).

```
solo key rng feedkernel
```
