DKG (Distributed Key Generation) module for generating threshold keys for BLS signatures.

This is an instatiation of the classical Pedersen DKG protocol that uses the blockchain as a broadcast channel.

# Configuration of the Pallet

The pallet requires two items in the configuration

- A vector of committee members `authorities` that are meant to execute the protocol.
- A `threshold: u64` that is between `1` and the total number of `authorities` that determines how many authorities need to provide signature shares in order to sign a message.


# Results of the Pallet Execution

There are two parts of output of the DKG protocol.

1. Private key -- the BLS private key of a committee member. This is present only in case the current node is one of `authorities` in the pallet configuration. In such a case, after the DKG has finalized, the private key can be read from the local storage of the Offchain Worker under the key `"dkw::threshold_secret_key"`. Since this part of the output is private it is not possible to read it from the pallet state.
2. Master Public key and Verification Public keys, one per committee member -- a collection of public BLS keys that are used to verify signature shares and the signature itself. These are public results of the DKG protocol and thus are kept in the pallet's storage. After the protocol has finished its execution, they can be fetched as a `keybox` struct by running `public_keybox_parts()`.


# Inner workings of the Pallet

The execution of the protocol is divided into 4 rounds, indexed 0, 1, 2, 3. Each round has a prespecified deadline in terms of the block height at which the round ends -- this is configured by setting `RoundEnds`. In each round the committee members are meant to send at most one message (in the form of a blockchain transaction). The more blocks between the subsequent rounds, the safer and more resistant agains network hiccups the protocol is.  The height at which the protocol terminates and the key is ready is `MasterKeyReady`. Below we briefly sketch the purpose of each protocol round

- Round 0 -- the committee members randomly generate a a secret key and post a single message which contains the corresponding public key that is used in subsequent rounds.
- Round 1 -- each committee member forms a proposal message that contains a commitment to a degree (t-1) (with t being the threshold) polynomial and list of encrypted shares, one per committee member (encrypted using the key posted in round 0). Note: the encryption is not yet implemented in Milestone 2 -- currently they are included in plaintext. This will be fixed in Milestone 3.
- Round 2 -- each committee member posts a sequence of disputes (along with proofs) which indicates which of the members acted dishonestly during round 2.
- Round 3 -- the disputes are summarized and all the members who were dishonest are "disqualified". The keys are then formed based on the honest submissions in Round 1.


License: Apache-2.0
