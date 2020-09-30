use sp_runtime::traits::Block as BlockT;

pub mod inherents;

// not sure if this should be even a trait?
pub trait Share<B: BlockT> {
	fn nonce(&self) -> B::Hash;
	fn member_id(&self) -> u32;
}

pub trait KeyBox<B: BlockT> {
	type S: Share<B>;

	// outputs Some(share) if we are a member of the committee and None otherwise
	fn generate_share(&self, nonce: B::Hash) -> Option<Self::S>;
	fn verify_share(&self, share: &Self::S) -> bool;
	// Some(share) if succeeded and None if failed for some reason (e.g. not enough shares) -- should add error handling later
	fn combine_shares(&self, shares: Vec<Self::S>) -> Option<Self::S>;
	// master share is the share with id=0, i.e., the combined signature for threshold signatures
	fn verify_master_share(&self, share: &Self::S) -> bool {
		match share.member_id() {
			0 => self.verify_share(share),
			_ => false,
		}
	}
	// Some(id) if a member of the committee and None otherwise
	fn my_id(&self) -> Option<u32>;
	// n_members and threshold should probably not be in this trait -- will see later
	fn n_members(&self) -> u32;
	fn threshold(&self) -> u32;
}

pub fn verify_randomness(_nonce: Vec<u8>, _random_bytes: Vec<u8>) -> bool {
	return true;
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_runtime::testing::H256;
	use std::collections::HashSet;
	use substrate_test_runtime_client::runtime::Block;
	struct TrivialShare {
		member_id: u32,
		nonce: H256,
		actual_share: u32,
	}

	impl Share<Block> for TrivialShare {
		fn nonce(&self) -> H256 {
			self.nonce.clone()
		}

		fn member_id(&self) -> u32 {
			self.member_id
		}
	}

	// these mock implementations can be at some point moved elsewhere
	struct TrivialKeyBox {
		my_id: Option<u32>,
		n_members: u32,
		threshold: u32,
	}

	impl KeyBox<Block> for TrivialKeyBox {
		type S = TrivialShare;
		fn generate_share(&self, nonce: H256) -> Option<TrivialShare> {
			match self.my_id {
				None => None,
				Some(id) => Some(TrivialShare {
					member_id: id,
					nonce: nonce,
					actual_share: id,
				}),
			}
		}

		fn verify_share(&self, share: &TrivialShare) -> bool {
			if share.member_id > self.n_members {
				return false;
			}
			return share.member_id == share.actual_share;
		}

		// if there are at least self.threshold correct, pairwise different share, then Some(master_share), else None
		fn combine_shares(&self, shares: Vec<TrivialShare>) -> Option<TrivialShare> {
			let mut unique_ids = HashSet::new();
			for share in shares.iter() {
				if self.verify_share(share) {
					unique_ids.insert(share.member_id);
				}
			}
			if (unique_ids.len() as u32) < self.threshold {
				return None;
			}
			let master_share = TrivialShare {
				member_id: 0,
				nonce: H256::default(),
				actual_share: 0,
			};
			Some(master_share)
		}

		fn my_id(&self) -> Option<u32> {
			self.my_id
		}
		fn n_members(&self) -> u32 {
			self.n_members
		}
		fn threshold(&self) -> u32 {
			self.threshold
		}
	}

	#[test]
	fn reject_wrong_share() {
		let key_box = TrivialKeyBox {
			my_id: Some(0),
			n_members: 10,
			threshold: 3,
		};
		let wrong_share_1 = TrivialShare {
			member_id: 11,
			nonce: H256::default(),
			actual_share: 11,
		};
		let wrong_share_2 = TrivialShare {
			member_id: 8,
			nonce: H256::default(),
			actual_share: 0,
		};

		assert_eq!(key_box.verify_share(&wrong_share_1), false);
		assert_eq!(key_box.verify_share(&wrong_share_2), false);
	}
}
