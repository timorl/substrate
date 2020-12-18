Randomness Beacon module for runtime providing unbiased, fair, and unpredictable randomness for every K-th block (with configurable K).

For full functionality, the gadgets from `sc-randomness-beacon` have to be used in runtime.
The necessary items are re-exported via the `sp-randomness-beacon` crate.

The current version relies on DKG pallet (pallet-dkg) to generate keys for the committee.

# Configuration of the Pallet

The pallet requires three items in the configuration

- `RANDOMNESS_PERIOD` specifies how often fresh random seed will be provided by the pallet.
- `START_HEIGHT` a block height that specifies when does the pallet start providing randomness. Concretely the randomness will come in blocks `START_HEIGHT + k*RANDOMNESS_PERIOD` for `k = 1, 2, 3, ...`.



# Inner workings of the Pallet

We refer to [our slides](https://docs.google.com/presentation/d/1DGCx_bqurKBfJUW28vkxBNHo_1mRvSfsqLqcEt-rgbU/edit?usp=sharing) explaining the high level idea of generating randomness from BLS signatures, the role of DKG, and how is this idea implemented in substrate. This also has some details on the architecture of the pallet.


License: Apache-2.0

