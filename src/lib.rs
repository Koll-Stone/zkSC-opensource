pub mod attrs;
pub mod com_forest;
pub mod com_tree;
pub mod compressed_pedersen;
pub mod link;
pub mod poseidon_utils;
pub mod pred;
pub mod proof_data_structures;
pub mod sparse_merkle;
pub mod test_util;
pub mod zk_utils;
pub mod util;
pub mod ecdsa;
pub mod zk_ac;
pub mod zk_ka;
pub mod zk_akkh;
#[cfg(feature = "python")]
pub mod python_exports;


pub type Error = Box<dyn ark_std::error::Error>;
pub use zk_utils::Bytestring;

use ark_crypto_primitives::commitment::{constraints::CommitmentGadget, CommitmentScheme};

pub type Com<C> = <C as CommitmentScheme>::Output;
pub type ComVar<C, CG, F> = <CG as CommitmentGadget<C, F>>::OutputVar;
pub type ComNonce<C> = <C as CommitmentScheme>::Randomness;
pub type ComNonceVar<C, CG, F> = <CG as CommitmentGadget<C, F>>::RandomnessVar;
pub type ComParam<C> = <C as CommitmentScheme>::Parameters;
pub type ComParamVar<C, CG, F> = <CG as CommitmentGadget<C, F>>::ParametersVar;
