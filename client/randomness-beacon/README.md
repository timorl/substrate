Integration of the randomness beacon module into substrate.

Disclaimer: This is a description of the state of the module in the first of three steps of
implementation. Because of that, there are a few mocks and TODOs left in the code. Moreover, since
an important component is missing at this stage (DKG -- to be added in the second milestone), running
this code within a client requires a bit of low-level code, like creating by hand some channels, etc.
In the final version, when all the components are ready, this will be cleaned up and made more friendly
from the perspective of integrating the randomness beacon into an existing project.

This crate provides a long-running future that collects randomness shares for subsequent blocks and
upon generating fresh randomness passes it to the block proposer who then places appropriate data in
inherent_data so that the randomness beacon pallet may inject it into a new block (as an inherent).

# Usage

First, create a block-import wrapper with the `RandomnessBeaconBlockImport::new` method. It requires
a writer end of a channel to send notifications that a new block has arrived and we should start
collecting a new randomness.

Next, using the reader end of the "new-block-arrived" notification channel construct an instance of
a service collecting shares with `RandomnessGossip::new` method. Moreover, it requires a writer end of
a channel to send fresh randomness.

Finally, using the reader end of the "fresh randomness" channel construct a `ProposeFactory` wrapper
with `authorship::ProposerFactory::new` method.

# Architecture rationale

Collecting shares of randomness is asynchronous with respect to block creation, so we use the block
proposer as a synchronization point, i.e. it waits until a fresh randomness for a respective block is
generated. When the randomness is ready, the proposer puts it in inherent data, and then the
randomness beacon pallet extracts the randomness and puts it into the new block.

License: Apache-2.0
