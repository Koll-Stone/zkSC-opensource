use ark_bls12_381::{Fr as BlsFr, FrParameters, Parameters};
use ark_crypto_primitives::{
  commitment::{CommitmentGadget, CommitmentScheme}, 
  crh::{TwoToOneCRH, TwoToOneCRHGadget},
  merkle_tree::TwoToOneParam,
};
use ark_ec::bls12::{self, Bls12};
// use ark_ec::bls12::Bls12;
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
  bits::boolean::Boolean,
  fields::fp::FpVar,
  prelude::EqGadget,
  ToBytesGadget,
};
use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon, PoseidonParameters};
// use arkworks_r1cs_gadgets::poseidon::FieldHasherGadget;
use arkworks_utils::Curve;
use ark_serialize::CanonicalSerialize;
use k256::ecdsa::VerifyingKey;
use core::{cmp::Ordering, marker::PhantomData};
use linkg16::groth16::{self, Proof, ProvingKey};
// use linkg16::groth16::{self, ProvingKey, VerifyingKey};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use crate::{
  com_tree::{ComTree, ComTreeConfig},
  poseidon_utils::{Bls12PoseidonCommitter, ComNonce}, 
  sparse_merkle::{constraints::SparseMerkleTreePathVar, SparseMerkleTreePath},
  zk_utils::{IdentityCRHGadget, UnitVar},
};
use ark_std::UniformRand;
// use groth16::Proof;
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

const ATTRLEN: usize = 8;
const TREE_HEIGHT: u32 = 16;
const TREE_NUM: usize = 64;

#[derive(Clone)]
pub struct ZkacProver<ConstraintF, AC, ACG, H, HG> 
where 
    ConstraintF: PrimeField,
    AC: CommitmentScheme,
    AC::Output: ToConstraintField<ConstraintF>,
    ACG: CommitmentGadget<AC, ConstraintF>,
    H: TwoToOneCRH,
    H::Output: ToConstraintField<ConstraintF>,
    HG: TwoToOneCRHGadget<H, ConstraintF>,
{
    pub height_hattr: u32,
    pub commit_param: AC::Parameters,
    pub crh_param: TwoToOneParam<ComTreeConfig<H>>,

    pub acpolicy: [u8; ATTRLEN],
    pub attr: [u8; ATTRLEN],
    pub ths: u8,
    pub hattr: AC::Output,
    pub root_star: H::Output,
    pub all_roots: [H::Output; TREE_NUM],
    pub hattr_auth_path: Option<SparseMerkleTreePath<ComTreeConfig<H>>>,
       
    pub res1: H::Output,
    pub res2: H::Output,
    pub i_b: H::Output,
    pub ik1: u8,
    pub ik2: H::Output,
    // New add time period
    pub tp: H::Output,
    pub temp_hash: H::Output,
    
    pub _marker: PhantomData<(ConstraintF, AC, ACG, H, HG, HG)>,
}


pub fn get_default_zkacprover() -> 
ZkacProver<BlsFr, Bls12PoseidonCommitter, Bls12PoseidonCommitter, Bls12PoseidonCrh, Bls12PoseidonCrh> {
    let circuit: ZkacProver<BlsFr, Bls12PoseidonCommitter, Bls12PoseidonCommitter, Bls12PoseidonCrh, Bls12PoseidonCrh> = ZkacProver {
        height_hattr: TREE_HEIGHT,
        crh_param: (), // MERKLE_CRH_PARAM.clone(),
        commit_param: (),

        
        acpolicy: [0_u8; ATTRLEN],
        attr: [0_u8; ATTRLEN],
        ths: 10_u8,
        hattr: Default::default(),
        root_star: Default::default(),
        all_roots: [Default::default(); TREE_NUM],
        hattr_auth_path: None,

        res1: Default::default(), // r1
        res2: Default::default(), // r2
        i_b: Default::default(), // B
        ik1: 9_u8,
        ik2: Default::default(), // k2
        _marker: PhantomData,
        // New add tp
        tp: Default::default(),
        temp_hash: Default::default(),
    };
    return circuit;
}


// value for a specific instance
pub struct ZkacproverWithValue {
    circuit: ZkacProver<BlsFr, Bls12PoseidonCommitter, Bls12PoseidonCommitter, Bls12PoseidonCrh, Bls12PoseidonCrh>,
    acpolicy_input: Vec<Fp256<FrParameters>>, 
    // root_hattr_input: Vec<Fp256<FrParameters>>,
    all_roots_input: Vec<Fp256<FrParameters>>,
    ths_input: Fp256<FrParameters>,
    res1_input: Vec<Fp256<FrParameters>>,
    res2_input: Vec<Fp256<FrParameters>>,
    tp_input: Vec<Fp256<FrParameters>>,
    temp_input: Vec<Fp256<FrParameters>>,
}

pub fn get_zkacprover_with_value(public_num: Vec<u8>) -> ZkacproverWithValue {
    // prepare input and witness
    let hasher = Poseidon::new(BLS12_POSEIDON_PARAMS.clone());

    let mut numrng = rand::thread_rng();

    let mut acpolicy: Vec<u8> = vec![0u8; ATTRLEN];
    let mut attr: Vec<u8> = vec![10u8; ATTRLEN];
    for i in 0..ATTRLEN {
        acpolicy[i] = numrng.gen();
        attr[i] = acpolicy[i]+1;
    }
    let nonce = {
        let nonce_seed = &ComNonce([0u8; 32]);
        let mut rng = ChaCha12Rng::from_seed(nonce_seed.0);
        <Bls12PoseidonCommitter as CommitmentScheme>::Randomness::rand(&mut rng)
    };
    let hattr = <Bls12PoseidonCommitter as CommitmentScheme>::commit(&(), &attr, &nonce).unwrap();

    let acpolicy_arr: [u8; ATTRLEN] = acpolicy.clone().try_into().unwrap();
    let attr_arr: [u8; ATTRLEN] = attr.clone().try_into().unwrap();
    let i_b = hasher.hash(&public_num.to_field_elements().unwrap()).unwrap(); // a random B in Fp256 which can be regarded as hash of the B used in DH that usually belongs to a larger field than Fp256.
    let input2: Vec<u8> = vec![9_u8]; // a random value for k1
    let hash_ik1 = <Bls12PoseidonCommitter as CommitmentScheme>::commit(&(), &input2, &nonce).unwrap();
    
    // User a random value to act as the tp
    let input4 : Vec<u8> = vec![8_u8];
    let tp = hasher.hash(&input4.to_field_elements().unwrap()).unwrap();

    // let hash_ik1 = hasher.hash(&input2.to_field_elements().unwrap()).unwrap();
    let input3: Vec<u8> = vec![200,200,200,200,200]; // a random value for k2
    let ik2 = hasher.hash(&input3.to_field_elements().unwrap()).unwrap();

    // Compute hash(attr, tp)
    let temp_hash = <Bls12PoseidonCrh as TwoToOneCRH>::evaluate(&(), &to_bytes!(hattr).unwrap(),&to_bytes!(tp).unwrap()).unwrap();
    let res1 = <Bls12PoseidonCrh as TwoToOneCRH>::evaluate(&(), &to_bytes!(temp_hash).unwrap(),&to_bytes!(hash_ik1).unwrap()).unwrap();
    let res2 = <Bls12PoseidonCrh as TwoToOneCRH>::evaluate(&(), &to_bytes!(i_b).unwrap(),&to_bytes!(ik2).unwrap()).unwrap();
    

    let leaf_idx = 9;
    let mut tree1 = ComTree::<_, Bls12PoseidonCrh,Bls12PoseidonCommitter>::empty((), TREE_HEIGHT);
    let auth_path1 = tree1.insert(leaf_idx, &hattr);
    let mut all_roots: Vec<Fp256<FrParameters>> = vec![Fp256::from(0); TREE_NUM];
    let another_root: Fp256<FrParameters> = Fp256::from(33); 
    for i in 0..TREE_NUM {
        // all_roots[i] = tree1.root();
        all_roots[i] = another_root.clone();
    }
    all_roots[TREE_NUM-1] = tree1.root();
    //  fill forest with wrogn root value except one correct value.
    let all_roots_arr = all_roots.clone().try_into().unwrap();


    let prover: ZkacProver<BlsFr, Bls12PoseidonCommitter, Bls12PoseidonCommitter, Bls12PoseidonCrh, Bls12PoseidonCrh> = ZkacProver {

        height_hattr: TREE_HEIGHT,
        crh_param: (), // MERKLE_CRH_PARAM.clone(),
        commit_param: (),

        acpolicy: acpolicy_arr,
        attr: attr_arr,
        ths: 10_u8,
        hattr: hattr,
        root_star: tree1.root(),
        all_roots: all_roots_arr,
        hattr_auth_path: Some(auth_path1.path.clone()),
        
        res1: res1,
        res2: res2,
        i_b: i_b,
        ik1: 9_u8,
        ik2: ik2,
        tp: tp,
        temp_hash: temp_hash,

        _marker: PhantomData,
    };

    // prepare public witness
    // let root_hattr_input = tree1.root().to_field_elements().unwrap();
    let ths_input = Fp256::from(10_u8);
    let res1_input = res1.to_field_elements().unwrap();
    let res2_input = res2.to_field_elements().unwrap();
    let temp_input = temp_hash.to_field_elements().unwrap();
    let mut tmp = res1_input.clone();
    tmp.clear();
    for i in 0..ATTRLEN {
        let x = Fp256::from(acpolicy[i]);
        tmp.push(x);
    }
    let acpolicy_input = tmp;
    // Add tp input 
    let tp_input = tp.to_field_elements().unwrap();

    ZkacproverWithValue {
        circuit: prover, 
        acpolicy_input: acpolicy_input, 
        ths_input: ths_input,
        // root_hattr_input: root_hattr_input,
        all_roots_input: all_roots,
        res1_input: res1_input, 
        res2_input: res2_input,
        tp_input: tp_input,
        temp_input: temp_input,
    }
}

impl<ConstraintF, AC, ACG, H,HG> ConstraintSynthesizer<ConstraintF> 
    for ZkacProver<ConstraintF, AC, ACG, H, HG>
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
        let mut acpolicy_var: Vec<FpVar<ConstraintF>> = vec![];
        for i in 0..ATTRLEN {
            let y = FpVar::new_input(ns!(cs, "policy fpvar"), || Ok(ConstraintF::from(self.acpolicy[i]))).unwrap();
            acpolicy_var.push(y);
        }
        let ths_var = FpVar::new_input(ns!(cs, "ths var"), || Ok(ConstraintF::from(self.ths))).unwrap();
        let mut all_roots_var: Vec<HG::OutputVar> = vec![];
        for i in 0..TREE_NUM {
            let y = HG::OutputVar::new_input(ns!(cs, "all roots component"), || Ok(self.all_roots[i].clone()))?;
            all_roots_var.push(y);
        }
        
        let res1_var = HG::OutputVar::new_input(ns!(cs, "res1 var"), || Ok(self.res1.clone()))?;
        let res2_var = HG::OutputVar::new_input(ns!(cs, "res2 var"), || Ok(self.res2.clone()))?;
        let temp_var = HG::OutputVar::new_input(ns!(cs, "temp var"), || Ok(self.temp_hash.clone()))?;
        let tp_var = HG::OutputVar::new_input(ns!(cs, "tp var"), || Ok(self.tp.clone()))?;

        // **************** witness ****************
        let root_var = HG::OutputVar::new_witness(ns!(cs, "root hattr var"), || Ok(self.root_star.clone()))?;
        let mut attr_var: Vec<FpVar<ConstraintF>> = vec![];
        for i in 0..ATTRLEN {
            let y = FpVar::new_witness(ns!(cs, "attr fpvar"), || Ok(ConstraintF::from(self.attr[i]))).unwrap();
            attr_var.push(y);
        }
        let mut attr_u8_var: Vec<UInt8<ConstraintF>> = vec![];
        for i in 0..ATTRLEN {
            attr_u8_var.push(UInt8::new_witness(ns!(cs, "attr u8 component"), || Ok(self.attr[i])).unwrap());
        }
        let mut ik1_u8_var: Vec<UInt8<ConstraintF>> = vec![];
        ik1_u8_var.push(UInt8::new_witness(ns!(cs, "ik1 u8 component"), || Ok(self.ik1)).unwrap());
        let leaf_param_var: UnitVar<ConstraintF> = UnitVar::default();
        let i_b_var = HG::OutputVar::new_witness(ns!(cs,"B_var"), || Ok(self.i_b.clone()))?;
        // let ik1_var = HG::OutputVar::new_witness(ns!(cs,"k1_var"), || Ok(self.ik1.clone()))?;
        let ik1_var = FpVar::new_witness(ns!(cs, "k1_var"), || Ok(ConstraintF::from(self.ik1))).unwrap();
        let ik2_var = HG::OutputVar::new_witness(ns!(cs,"k2_var"), || Ok(self.ik2.clone()))?;

        // **************** constants ****************
        let crh_param_var =
            HG::ParametersVar::new_constant(ns!(cs, "two_to_one param"), &self.crh_param)?;
        let commit_param_var = ACG::ParametersVar::new_constant(ns!(cs, "commit param"), &self.commit_param)?;
        ACG::ParametersVar::new_constant(ns!(cs, "commit param"), &self.commit_param)?;
        let nonce_var = {
            let nonce_seed = &ComNonce([0u8; 32]);
            let mut rng = ChaCha12Rng::from_seed(nonce_seed.0);
            let nonce = AC::Randomness::rand(&mut rng);
            ACG::RandomnessVar::new_witness(ns!(cs, "nonce_var"), || Ok(nonce))?
        };

        
        // **************** check satisfy or not ****************
        for i in 0..ATTRLEN {
            attr_var[i].enforce_cmp(&acpolicy_var[i], Ordering::Greater, true)?;
        }
        let hash_of_attr = <ACG as CommitmentGadget<AC, ConstraintF>>::commit(&commit_param_var, &attr_u8_var, &nonce_var).unwrap();
        let leaf_hattr_var =
            ACG::OutputVar::new_witness(ns!(cs, "leaf hattr com var"), || Ok(self.hattr.clone()))?;
        hash_of_attr.enforce_equal(&leaf_hattr_var)?;

        ik1_var.enforce_cmp(&ths_var, Ordering::Less,true)?;
        let hash_of_ik1 = <ACG as CommitmentGadget<AC, ConstraintF>>::commit(&commit_param_var, &ik1_u8_var, &nonce_var).unwrap();

        

        let auth_path_hattr = self.hattr_auth_path.clone().unwrap_or_else(|| default_auth_path::<AC, H>(self.height_hattr));
        let path_hattr_var = SparseMerkleTreePathVar::<_, IdentityCRHGadget, HG, _>::new_witness(
            ns!(cs, "auth path"),
            || Ok(auth_path_hattr),
            self.height_hattr,
        )?;

        path_hattr_var.check_membership(
            ns!(cs, "check_membership hattr").cs(),
            &leaf_param_var,
            &crh_param_var, 
            &root_var, 
            &leaf_hattr_var,
        )?;

        let tmp1 = <HG as TwoToOneCRHGadget<H, ConstraintF>>::evaluate(&crh_param_var, &hash_of_attr.to_bytes().unwrap(), &tp_var.to_bytes().unwrap()).unwrap();
        tmp1.enforce_equal(&temp_var)?;

        let tmp2 = <HG as TwoToOneCRHGadget<H, ConstraintF>>::evaluate(&crh_param_var, &temp_var.to_bytes().unwrap(), &hash_of_ik1.to_bytes().unwrap()).unwrap();
        tmp2.enforce_equal(&res1_var)?;

        let tmp3 = <HG as TwoToOneCRHGadget<H, ConstraintF>>::evaluate(&crh_param_var, &i_b_var.to_bytes().unwrap(), &ik2_var.to_bytes().unwrap()).unwrap();
        tmp3.enforce_equal(&res2_var)?;

        

        let mut is_member = Boolean::FALSE;
        for root in all_roots_var {
            is_member = is_member.or(&root_var.is_eq(&root)?)?;
        }
        is_member.enforce_equal(&Boolean::TRUE)?;


        // All done
        Ok(())
    }
}


pub fn default_auth_path<AC, H>(height: u32) -> SparseMerkleTreePath<ComTreeConfig<H>>
where
    AC: CommitmentScheme,
    H: TwoToOneCRH,
{
    let default_com_bytes = to_bytes!(AC::Output::default()).unwrap();
    SparseMerkleTreePath::<ComTreeConfig<H>> {
        leaf_hashes: (default_com_bytes.clone(), default_com_bytes),
        inner_hashes: vec![
            (H::Output::default(), H::Output::default());
            height.checked_sub(2).expect("tree height cannot be < 2") as usize
        ],
        root: H::Output::default(),
    }
}



pub fn runzkactest(public_num: Vec<u8>) -> (bool, Duration) {
    let _rng = ark_std::test_rng();
    let mut total_time: Duration = Duration::new(0, 0);
    let mut proof_time: Duration = Duration::new(0, 0);
    let mut verify_time: Duration = Duration::new(0, 0);

    let default_circuit = get_default_zkacprover();
    let mut rng = ark_std::test_rng();
    let pk: ProvingKey<ark_bls12_381::Bls12_381> = groth16::generate_random_parameters(default_circuit, &mut rng).unwrap();
    let vk = pk.verifying_key();
    //println!("pk size is {} bytes, vk size is {} bytes", pk.serialized_size(), vk.serialized_size());
    
    let loopnum=10;
    let mut start = Instant::now();
    for _i in 0..loopnum {
        let zkacwithvalue = get_zkacprover_with_value(public_num.clone());
        groth16::create_random_proof(zkacwithvalue.circuit, &pk, &mut rng).unwrap();
    }  
    let mut duration = start.elapsed();
    proof_time = duration / loopnum;
    //println!("generate_proof for access took: {:?} in {} running", duration,loopnum);
    // start = Instant::now();
    // for _i in 1..loopnum {
    //     let _zkacwithvalue = get_zkacprover_with_value();
    // }  
    // duration = start.elapsed();
    //println!("preparing circuit for access proof: {:?} in {} running", duration,loopnum);

    let zkacwithvalue = get_zkacprover_with_value(public_num);
    let mut all_inputs = zkacwithvalue.acpolicy_input;
    all_inputs.push(zkacwithvalue.ths_input);
    all_inputs = [all_inputs, zkacwithvalue.all_roots_input, zkacwithvalue.res1_input, zkacwithvalue.res2_input, zkacwithvalue.temp_input, zkacwithvalue.tp_input].concat();
    // let mut start = Instant::now();
    // let proof = groth16::create_random_proof(zkacwithvalue.circuit, &pk, &mut rng).unwrap();
    // let duration = start.elapsed();
    // total_time += duration;
    //println!("generate_proof for one running took: {:?} ", duration);
    //println!("proof size: {} bytes", proof.serialized_size());  
    //println!("verify_proof for access tx took: {:?} in  1 runnings, res {}", duration, vres);
    let proof = groth16::create_random_proof(zkacwithvalue.circuit, &pk, &mut rng).unwrap();
    start = Instant::now();
    for _i in 0..loopnum {
        groth16::verify_proof(&vk, &proof, &all_inputs).unwrap();
    }
    duration = start.elapsed();
    let vres = groth16::verify_proof(&vk, &proof, &all_inputs).unwrap();
    verify_time = duration / loopnum;
    total_time = proof_time + verify_time;
    (vres, total_time)
    
}

#[cfg(test)]
mod test {

    use crate::zk_ac::runzkactest;

    #[test]
    fn test_zkacprover() {
        let public_num: Vec<u8> = vec![100,100,100,100,100];
        runzkactest(public_num);
        assert!(true);
        
    }
}