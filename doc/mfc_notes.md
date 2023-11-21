# mfc card types

Some information about MFC cards and their vulnerabilities

## original card
the first cards original and first China's clones

Have the first version of the PRNG. `Weak PRNG`

Vulnerable:
1. card-only dark side attack (`hf mf darkside`)
2. card-only nested attack (`hf mf nested`)
3. decode card-reader trace (`data list`)

## Fixed PRNG cards
the first cards original and first China's clones

Have the next version of the PRNG. `Strong PRNG`. The nested auth has not changed. Dark-side attack is not possible.

Vulnerable:
1. card-only hardnested attack (`hf mf hardnested`)
2. decode card-reader trace

## Static nonce cards

The first revision of China's cards tried to fix holes in the card's auth
Cards have static nonce instead of dynamic. The nonce is just the same for each authentication.

Have the next version of the PRNG. The nested auth has not changed. Dark-side attack is not possible.

Vulnerable:
1. card-only staticnested attack (`hf mf staticnested`)
2. decode card-reader trace

## Static encrypted nonce cards

For the first auth, it has the first version of the PRNG. `Weak PRNG`

For the nested, the card has a nonce that is some function of auth+card's data instead of dynamic. 
The nonce is just the same for each auth with the same parameters.

(in progress...)

Vulnerable:
1. decode card-reader trace

## reader-only attack

The readers have a random generator bug. With it, we can recover a key for the sector it tries to authenticate.
