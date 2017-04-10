# WSU-CRYPT

WSU-CRYPT is encryption and decryption program based on Twofish by Bruce Schneier, John Kelsey, Doug Whiting, David Wagner, Chris Hall and SKIPJACK which was created by the NSA. WSU-CRYPT is implemented using a 64 bit block size and a 64 bit key.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. To view README properly, open in your favorite markdown editor

### Building & Installing

* Unpack tar.gz - will extract a folder called `WSU-CRYPT`
* Built with python 2.7 which should be installed on all macs.
* navigate to folder `WSU-CRYPT` through terminal
* To run program enter `python wsu-crypt.py`
* Program will create the file `output.txt` where it will write the encrypted text
  and decrypted text for quick viewing.

Note:

* You can change the key by editing the file `key.txt`

  Key must be in hex and 16 characters long. (16 hex * 4 bits per hex = 64 bits)

* You can change your ascii text input by editing `plaintext.txt`

  Plaintext must be in ascii. The code will convert to hex when it reads file.

* When adding new text to `plaintext.txt` or `key.txt` make sure there are no carriage returns or new lines. Turning on line wrapping in text editor helps here.

BAD:

```
    Computer science is the study of the theory, experimentation,
    and engineering that form the basis for the design and use
    of computers. It is the scientific and practical approach to
    computation and its applications and the systematic study of
    the feasibility, structure, expression, and mechanization of
    the methodical procedures (or algorithms) that underlie the
    acquisition, representation, processing, storage, communication
    of, and access to information. An alternate, more succinct definition
    of computer science is the study of automating algorithmic processes
    that scale. A computer scientist specializes in the theory of computation
    and the design of computational systems.[1]
```

GOOD:

``` markdown
Computer science is the study of the theory, experimentation, and engineering that form the basis for the design and use of computers. It is the scientific and practical approach to computation and its applications and the systematic study of the feasibility, structure, expression, and mechanization of the methodical procedures (or algorithms) that underlie the acquisition, representation, processing, storage, communication of, and access to information. An alternate, more succinct definition of computer science is the study of automating algorithmic processes that scale. A computer scientist specializes in the theory of computation and the design of computational systems.[1]
```

### Archive

Contents of `WSU-CRYPT`

```txt
WSU-CRYPT
    ├── README.md           Contains README for project
    ├── key.txt             Holds the 16 digit hex key (64 bits)
    ├── output.txt          Output of encrypt plain text and decrypt plain text
    ├── plaintext.txt       Holds the plain text (ASCII)
    ├── plaintext-long.txt  Holds the long plain text (ASCII)
    └── wsu-crypt.py        Code to encrypt/decrypt plaintext with provided key
```

## Running wsu-crypt.py

1. When running `wsu-crypt.py` first the program will grab the key from the file
   `key.txt`

1. Using the key it will generate the subkey tables for encryption and decryption
   and output those to the console.

   EXAMPLE:

   ``` txt
   Generated Encrypt Sub Keys:
    0:['57', '37', '78', '12', '79', '7b', '80', '23', '9b', 'bc', '9', '34']
    1:['ac', 'e2', 'd5', 'cd', 'cf', '26', '5e', 'de', 'f1', '6a', 'e6', 'ef']
    2:['2', '8d', '2b', '78', '24', 'd1', 'b3', '89', '46', '15', '3c', '9a']
    3:['79', '7b', '80', '23', '9b', 'bc', '9', '34', 'bd', 'c0', '91', '45']
    4:['cf', '26', '5e', 'de', 'f1', '6a', 'e6', 'ef', '13', 'af', '6f', 'f0']
    5:['24', 'd1', 'b3', '89', '46', '15', '3c', '9a', '68', '59', 'c4', 'ab']
    6:['9b', 'bc', '9', '34', 'bd', 'c0', '91', '45', 'de', '4', '1a', '56']
    7:['f1', '6a', 'e6', 'ef', '13', 'af', '6f', 'f0', '35', 'f3', 'f7', '1']
    8:['46', '15', '3c', '9a', '68', '59', 'c4', 'ab', '8a', '9e', '4d', 'bc']
    9:['bd', 'c0', '91', '45', 'de', '4', '1a', '56', 'e0', '48', 'a2', '67']
    10:['13', 'af', '6f', 'f0', '35', 'f3', 'f7', '1', '57', '37', '78', '12']
    11:['68', '59', 'c4', 'ab', '8a', '9e', '4d', 'bc', 'ac', 'e2', 'd5', 'cd']
    12:['de', '4', '1a', '56', 'e0', '48', 'a2', '67', '2', '8d', '2b', '78']
    13:['35', 'f3', 'f7', '1', '57', '37', '78', '12', '79', '7b', '80', '23']
    14:['8a', '9e', '4d', 'bc', 'ac', 'e2', 'd5', 'cd', 'cf', '26', '5e', 'de']
    15:['e0', '48', 'a2', '67', '2', '8d', '2b', '78', '24', 'd1', 'b3', '89']
   ```

1. Then the program will read `plaintext.txt` and divide the ascii text into 64 bit hex blocks.

1. Each hex block will be fed into the encrypt function one at a time with the encryption logic
   shown on each of the 16 passes.

   EXAMPLE:

   ```txt
    =============================== ENCRYPT ====================================
    Block 1 of 86
    Plain text: Computer
    Encoded plain text: 436f6d7075746572 Key: abcdef0123456789
    After Whiting: e8a28271563102fb
    This is round 0
    g1:e8 g2:a2 g3:cd g4:98 g5:c5 g6:39
    g1:82 g2:71 g3:31 g4:6b g5:fe g6:ed
    t0:c539 t1:feed
    f0:5ecf f1:9293
    After one round: 47f9765e8a28271
    ...
   ```

1. After whole text in encrypted, the decrypt function will be called on the encrypted text
   in the same manner.

   EXAMPLE:

   ``` txt
    ============================== DECRYPT ===================================
    Block 71 of 86
    Encrypted text: d1061326fa863c6c Key: abcdef0123456789
    After Whiting: 7acbfc27d9c35be5
    This is round 0
    g1:7a g2:cb g3:b9 g4:a7 g5:f1 g6:28
    g1:fc g2:27 g3:d g4:65 g5:22 g6:e5
    t0:f128 t1:22e5
    f0:5bc3 f1:b8be
    After one round: e844f1ad7acbfc27
    ...
   ```

1. The whole encrypted text and decrypted text will be wrote to `output.txt`

1. Finally, The console will output the encrypted text and decrypted text. (same as `output.txt`)

## Test Files

By default, `wsu-encrypt.py` will pull text from `plaintext.txt`

To run a longer test you can run it against `plaintext-long.txt` by changing:

```python
438  # Get the encoded plaintext file
439  #plain_text = get_text("plaintext.txt")          # comment out to run long text
440  plain_text = get_text("plaintext-long.txt")   # uncomment to run long text
```

## Caveats

Had some troubles with just copy/pasting paragraphs from wikipedia due to formatting.
Make sure if you copy/paste that the whole paragraph resides on one line of txt file.

## Built With

* Python - V2.7

## Authors

* **Spencer Kitchen** 
  * email: spencer.kitchen@wsu.edu