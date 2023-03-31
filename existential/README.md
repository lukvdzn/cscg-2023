### ID: torukmagto

# Cracking ECDSA

## Approach
As explicitely mentioned in the source code of the `ecdsa` library, it is vital that the nonce `k` during the signing
process is random and never leaked. Nonce reusage and leakage makes it possible to recover the private key.
However, papers have also shown that even few bits leakage of `k` could potentially disclose the private key ([LadderLeak](https://eprint.iacr.org/2020/615.pdf)).
In this case, the [client.py](./challenge-files/client.py)
implementation sets the least significant 128 bits of `k` to a random value, but sets the upper 128 bits to the hash of
the message to sign. Therefore, it is possible to deduce
`k` and thus the private key. 

We let the oracle sign at least 2 signatures for an arbitrary message, which we **reuse throughout all** signings, and then
execute the *Lattice Attack* according to this [guide](https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/). The signatures are manually collected in [signatures.txt](./signatures.txt) after each signing. The arbitrary message `0111` is hardcoded in the exploit script [crack_ecdsa.py](./crack_ecdsa.py), if needed, one can extract it.

The probability that `k` can be recovered grows with more collected message-signature pairs,
4 pairs sufficed in our case.

## Flag
``CSCG{OwNowHowDidYouDoThat}``