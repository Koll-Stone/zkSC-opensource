use ark_bls12_381::{Fr as BlsFr, FrParameters};
use ark_crypto_primitives::{
  commitment::{CommitmentGadget, CommitmentScheme}, 
  crh::{TwoToOneCRH, TwoToOneCRHGadget},
  merkle_tree::TwoToOneParam,
};
use ark_ec::bls12::Bls12;
use ark_ff::{PrimeField, ToConstraintField, to_bytes, Fp256};   
use ark_relations::{
  ns, 
  r1cs::{
    ConstraintSynthesizer, 
    ConstraintSystemRef, 
    SynthesisError,
  },
};
use ark_r1cs_std::{
  alloc::AllocVar, 
  bits::uint8::UInt8,
  fields::fp::FpVar,
  prelude::EqGadget,
  ToBytesGadget,
};
use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon, PoseidonParameters};
use arkworks_r1cs_gadgets::poseidon::FieldHasherGadget;
use arkworks_utils::Curve;
use ark_serialize::CanonicalSerialize;
use core::{cmp::Ordering, marker::PhantomData};
use linkg16::groth16::{self, ProvingKey, VerifyingKey};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use crate::{
  com_tree::{ComTree, ComTreeConfig},
  poseidon_utils::{Bls12PoseidonCommitter, ComNonce}, 
  sparse_merkle::{constraints::SparseMerkleTreePathVar, SparseMerkleTreePath},
  zk_utils::{IdentityCRHGadget, UnitVar},
};
use ark_std::UniformRand;
use groth16::Proof;
use lazy_static::lazy_static;
use std::time::{Duration, Instant};

use crate::poseidon_utils::
{
    // Bls12PoseidonCommitter,
    Bls12PoseidonCrh,
    setup_poseidon_params,
};


lazy_static! {
    static ref BLS12_POSEIDON_PARAMS: PoseidonParameters<BlsFr> =
        setup_poseidon_params(Curve::Bls381, 3, 5);
}


#[derive(Clone)]
pub struct ZkkaProver<ConstraintF, AC, ACG, H, HG> 
where 
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{

    pub crh_param: TwoToOneParam<ComTreeConfig<H>>,

    pub res2: H::Output,
    pub i_b: H::Output,
    pub ik2: H::Output,
    
    pub _marker: PhantomData<(ConstraintF, AC, ACG, H, HG, HG)>,
}


fn get_default_zkkaprover() -> 
ZkkaProver<BlsFr, Bls12PoseidonCommitter, Bls12PoseidonCommitter, Bls12PoseidonCrh, Bls12PoseidonCrh> {
    let circuit: ZkkaProver<BlsFr, Bls12PoseidonCommitter, Bls12PoseidonCommitter, Bls12PoseidonCrh, Bls12PoseidonCrh> = ZkkaProver {

        crh_param: (), // MERKLE_CRH_PARAM.clone(),

        res2: Default::default(), // r2
        i_b: Default::default(), // B
        ik2: Default::default(), // k2
        _marker: PhantomData,
    };
    return circuit;
}

// value for a specific instance
pub struct ZkkaproverWithValue {
    circuit: ZkkaProver<BlsFr, Bls12PoseidonCommitter, Bls12PoseidonCommitter, Bls12PoseidonCrh, Bls12PoseidonCrh>,
    i_b_input: Vec<Fp256<FrParameters>>,
    res2_input: Vec<Fp256<FrParameters>>,
}

fn get_zkkaprover_with_value(public_num: Vec<u8>) -> ZkkaproverWithValue {
    // prepare input and witness
    let hasher = Poseidon::new(BLS12_POSEIDON_PARAMS.clone());
        
    // let mut numrng = rand::thread_rng();

    //let input1: Vec<u8> = vec![2,2,2,2,2]; // a random value for B
    let i_b = hasher.hash(&public_num.to_field_elements().unwrap()).unwrap();
    let input3: Vec<u8> = vec![200,200,200,200,200]; // a random value for k2
    let ik2 = hasher.hash(&input3.to_field_elements().unwrap()).unwrap();

    let res2 = <Bls12PoseidonCrh as TwoToOneCRH>::evaluate(&(), &to_bytes!(i_b).unwrap(),&to_bytes!(ik2).unwrap()).unwrap();

    
    let prover: ZkkaProver<BlsFr, Bls12PoseidonCommitter, Bls12PoseidonCommitter, Bls12PoseidonCrh, Bls12PoseidonCrh> = ZkkaProver {
        
        crh_param: (), // MERKLE_CRH_PARAM.clone(),
        res2: res2,
        i_b,
        ik2: ik2,

        _marker: PhantomData,
    };

    // prepare public witness
    let res2_input = res2.to_field_elements().unwrap();


    ZkkaproverWithValue { 
        circuit: prover, 
        i_b_input: i_b.to_field_elements().unwrap(),
        res2_input: res2_input,
    }
}

impl<ConstraintF, AC, ACG, H,HG> ConstraintSynthesizer<ConstraintF> 
    for ZkkaProver<ConstraintF, AC, ACG, H, HG>
where 
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<ConstraintF>) -> Result<(), SynthesisError> {

        // **************** initialize gadgets ****************
        // **************** input ****************
        let res2_var = HG::OutputVar::new_input(ns!(cs, "res2 var"), || Ok(self.res2.clone()))?;
        let i_b_var = HG::OutputVar::new_input(ns!(cs,"B_var"), || Ok(self.i_b.clone()))?;

        // **************** witness ****************
        let ik2_var = HG::OutputVar::new_witness(ns!(cs,"k2_var"), || Ok(self.ik2.clone()))?;

        // **************** constants ****************
        let crh_param_var =
            HG::ParametersVar::new_constant(ns!(cs, "two_to_one param"), &self.crh_param)?;

        // **************** check satisfy or not ****************
        let tmp2 = <HG as TwoToOneCRHGadget<H, ConstraintF>>::evaluate(&crh_param_var, &i_b_var.to_bytes().unwrap(), &ik2_var.to_bytes().unwrap()).unwrap();
        tmp2.enforce_equal(&res2_var)?;



        // All done
        Ok(())
    }
}



pub fn runzkkatest(public_num: Vec<u8>) -> (bool, Duration) {
    let loopnum=10;
    let mut total_time = Duration::new(0, 0);
    let mut proof_time = Duration::new(0, 0);
    let mut verify_time = Duration::new(0, 0);
    let _rng = ark_std::test_rng();
    let default_circuit = get_default_zkkaprover();
    let mut rng = ark_std::test_rng();
    let pk: ProvingKey<ark_bls12_381::Bls12_381> = groth16::generate_random_parameters(default_circuit, &mut rng).unwrap();
    let vk = pk.verifying_key();
    //println!("pk size is {} bytes, vk size is {} bytes", pk.serialized_size(), vk.serialized_size());

    let mut start = Instant::now();
    //println!("generate_proof for key agreement took: {:?} ", duration);
    for _i in 0..loopnum {
        let zkkawithvalue = get_zkkaprover_with_value(public_num.clone());
        groth16::create_random_proof(zkkawithvalue.circuit, &pk, &mut rng).unwrap();
    }
    let mut duration = start.elapsed();
    proof_time = duration / loopnum;
    // let mut duration = start.elapsed();
    // println!("generate_proof for key agreement took: {:?} in {} running", duration,loopnum);
    // start = Instant::now();
    // for _i in 1..loopnum {
    //     let _zkkawithvalue = get_zkkaprover_with_value();
    // }
    // duration = start.elapsed();
    // println!("preparing circuit for key agreement proof took: {:?} in {} running", duration,loopnum);
    



    
    let zkkawithvalue = get_zkkaprover_with_value(public_num.clone());
    let thecircuit = zkkawithvalue.circuit;
    let all_inputs = [zkkawithvalue.res2_input,zkkawithvalue.i_b_input].concat();
    let proof = groth16::create_random_proof(thecircuit, &pk, &mut rng).unwrap();
    
    start = Instant::now();
    for _i in 0..loopnum {
        groth16::verify_proof(&vk, &proof, &all_inputs).unwrap();
    }
    duration = start.elapsed();
    verify_time = duration / loopnum;
    //println!("proof size: {} bytes", proof.serialized_size());
    //println!("verify_proof for key agreement took: {:?} in 1 runnings, res {}", duration, vres);
    let vres = groth16::verify_proof(&vk, &proof, &all_inputs).unwrap();
    total_time = proof_time + verify_time;
    (vres, total_time)
}

#[cfg(test)]
mod test {

    use crate::zk_ka::runzkkatest;

    #[test]
    fn test_zkkaprover() {
        let public_num: Vec<u8> = vec![1,2,3,4,5];
        runzkkatest(public_num);
        assert!(true);
        
    }
}