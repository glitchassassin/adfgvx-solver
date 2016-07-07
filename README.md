## ADFGVX Cipher Solver

This rough code is provided for anyone who wants to reverse-engineer my methods and create their own ADFGVX solver. It may or may not work out-of-the-box. I didn't build it to redistribute. Use at your own risk.

### Algorithm

I used ideas [from this thread](http://s13.zetaboards.com/Crypto/topic/6746690/1/) to hammer out my algorithm. There are other ways to achieve the same goal, and this might not be the best - but it works.

1. Pick a transposition key length to work with. Because of the grid transposition, this will usually be a factor of the length of ciphertext (e.g., a text with a length of 20 probably has a key of 4 or 5 characters).
2. For every possible transposition key of the given length:
   * Calculate the [Index of Coincidence](https://en.wikipedia.org/wiki/Index_of_coincidence) (IC) for the digrams (sets of two characters) in the ciphertext
   * Store the [forty highest unique ICs](/st "Completely random text has an IC of about 1, while English has an IC of about 1.73. The higher ICs are more likely to represent 'English-like' ciphered text.") and their corresponding transposition keys.
3. Generate a list of valid configurations for each of those transposition keys (see below for theory), sorted by IC from highest (most-English-like) to lowest.
4. For each valid configuration:
   * Convert the digrams to monograms and treat as a simple substitution cipher.
   * Run the converted ciphertext through a substitution cipher solver for some number of iterations (higher iterations = more accurate but lower performance)
   * Print/keep the best candidate for plaintext and continue

You'll usually recognize valid words and constructions in the plaintext even if the substitution solver doesn't completely translate it. From there, you can plug it into a decoder and tweak the alphabet grid by hand until it's complete.

### Identifying Valid Transposition Keys

If two transposition keys have the same index of coincidence (IC), it's usually because the columns are aligned to create the same digrams in both cases. For example, the following transpositions have the same IC:

    1 2 3 4  3 4 1 2  2 1 4 3
    A D F G  F G A D  D A G F
    V X A F  A F V X  X V F A
    G X D V  D V G X  X G V D

This usually happens when the key length is even. This allows us to use a shortcut.

The ADFGVX cipher replaces each letter of plaintext with two letters of ciphertext: a "row" letter and a "column" letter. For even-length keys, this means that the transposed columns will end up having all "row" letters or all "column" letters.

The transposition keys with a high Index of Coincidence *probably* have their column-columns and row-columns lined up with each other. We just need to figure out the correct order for each row-column combination - which is half as much work as testing *every* possible transposition key. 

So, we generate a list of permutations for each of the best transposition keys. If your key is 10 digits long, that's only 4,080 permutations to test. It's much lower for shorter keys.

Upon reflection, I'm not positive if this method should still work with odd-length keys, but it was successful in cracking the challenge cipher I was given. I'll leave that as an exercise to the reader.

## Credits

* Thanks to /r/HiroshiKatsuro for the crypto challenge.
* Thanks to Revelation (and everyone else in the thread) at the Crypto Forum for the algorithm inspiration.
* Thanks to [PracticalCryptography.com](http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-simple-substitution-cipher/) for the substitution solver & n-gram score algorithms.