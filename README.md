# Implementation of the Manx AE modes

## What is Manx?

Manx is a family of two authenticated encryption modes, namely Manx1 and Manx2, finely tuned for very short inputs.
More precisely, when instantiated with an n-bit block cipher, the total input length (i.e. the nonce, associated data and message) has to be less than 2n. Both modes require at most two cipher calls only.
For more details, see the paper [Authenticated Encryption for Very Short Inputs](https://eprint.iacr.org/2023/361) by Kazuhiko Minematsu, Junji Shikata and myself published in the CT-RSA 2023 proceedings. 

## Cipher-agnostic implementations

The Manx implementations provided in this repository are cipher-agnostic in the sense that the internal functions related to the underlying block cipher (i.e. key expansion and block encryption/decryption) are passed as arguments rather than being hardcoded.
This way, it is easy to instantiate Manx with your favorite block cipher dynamically for tests/benchmarks purposes.
However, note that the block cipher implementation should follow some requirements, see the `manx/README.md` file for more details.

## Structure of the repository

The repository structure is as follows:

```
manx_ae
│
├───manx
│   
├───manx-aes128
│   ├───armv7m
│   └───avr8
│   └───x86_64
```

The `manx` folder contains the generic implementations of Manx1 and Manx2: instructions on how to plug your favorite block cipher are given in the folder-specific README.
The `manx-aes128` folder contains implementations of Manx1 and Manx2 instantiated with different AES implementations listed by platform. See the folder-specific README files for more information.

## License

The code related to the Manx AE modes released in this repository is under [CC0 license](https://creativecommons.org/publicdomain/zero/1.0/deed.en).
However, some block cipher implementations included in this repository might be under other licenses. If so, a folder-specific LICENSE file will be included. For instance, the AES implementations on AVR are based on [the work from B. Poettering](http://point-at-infinity.org/avraes/) which is under the [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0.html).
