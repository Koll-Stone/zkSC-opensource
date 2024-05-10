use crate::{zk_ac, zk_ka, ecdsa, poseidon_utils::{Bls12PoseidonCrh,
    setup_poseidon_params,},};
use static_dh_ecdh::ecdh::ecdh::{ECDHNISTP256, KeyExchange, ToBytes};
use std::{fs::File, io::Write, time::{Duration, Instant}};
use lazy_static::lazy_static;
use arkworks_native_gadgets::poseidon::{FieldHasher, Poseidon, PoseidonParameters};
use arkworks_utils::Curve;
use ark_bls12_381::Fr as BlsFr;
use ark_ff::{PrimeField, ToConstraintField, to_bytes, BigInteger};
use ark_crypto_primitives::crh::TwoToOneCRH; 


// Define the space-ground latency and inter-SAP delay
const SPACE_GROUND_LATENCY: [Duration; 7] = [
    Duration::from_millis(5),
    Duration::from_millis(10),
    Duration::from_millis(15),
    Duration::from_millis(20),
    Duration::from_millis(25),
    Duration::from_millis(30),
    Duration::from_millis(35)
];

const INTER_SAP_DELAY: [Duration; 1] = [
    // Duration::from_millis(10),
    // Duration::from_millis(15),
    // Duration::from_millis(20),
    // Duration::from_millis(25),
    Duration::from_millis(30),
];

lazy_static! {
    static ref BLS12_POSEIDON_PARAMS: PoseidonParameters<BlsFr> =
        setup_poseidon_params(Curve::Bls381, 3, 5);
}





pub fn test_aka() {

    let mut f_end_to_end_latency = File::create("end_to_end_latency.csv").unwrap();
    let mut end_to_end_latency:Duration = Duration::new(0, 0);
    let mut time:Duration = Duration::new(0, 0);
    let mut vres: bool = false;
    let mut start = Instant::now(); 
    let mut duration = Duration::new(0, 0);
    let mut i = 0;

    for latency in SPACE_GROUND_LATENCY.iter() {
        let mut accres = 0;
        let mut loopnum = 5;
        for _ in 0..loopnum {
            end_to_end_latency = Duration::new(0, 0);
            println!("********     The {}th test begin !!!!      ********", i);
            println!("The space-ground latency is {:?}", latency);
            //UE prepare the private_num and public_num using in the key agreement
            let ue_private_num = ECDHNISTP256::generate_private_key([13; 32]);
            let ue_public_num = ECDHNISTP256::generate_public_key(&ue_private_num);

            //UE create the proof(include attr and k)
            println!("Create and Verifying Proof!!!!");
            (vres, time) = zk_ac::runzkactest(ue_public_num.to_bytes().to_vec());
            end_to_end_latency += time;
            if vres {
                
            } else {
                println!("The ac proof is invalid");
            }
            println!("the attr proof time taken is {:?}", time);

            // UE send the public_num to AP, add a space-groud link latency
            end_to_end_latency += *latency;

            // AP generate the private_num and public_num
            let (ap_sk, ap_vk) = ecdsa::generate_keypair();
            start = Instant::now();
            let ap_private_num = ECDHNISTP256::generate_private_key([14; 32]);
            let ap_public_num = ECDHNISTP256::generate_public_key(&ap_private_num);
            let ap_signature = ecdsa::sign_u8_type(&ap_sk, &ap_public_num.to_bytes());
            duration = start.elapsed();
            end_to_end_latency += duration;
            println!("the sign signature time taken is {:?}", duration);

            // AP send the signature to UE, add a space-groud link latency
            end_to_end_latency += *latency;

            // UE verify the signature and send the zk proof(k2) to AP
            start = Instant::now();
            let mut is_valid: bool = ecdsa::verify_signature(&ap_vk, &ap_public_num.to_bytes(), &ap_signature);
            duration = start.elapsed();
            end_to_end_latency += duration;
            println!("the verify signature time taken is {:?}", duration);

            (vres, time) = zk_ka::runzkkatest(ue_public_num.to_bytes().to_vec());
            if vres {
                end_to_end_latency += time;
            } else {
                println!("The ka proof is invalid");
            }
            println!("the ka proof time taken is {:?}", time);
            
            // Send ka proof to AP, add a space-groud link latency
            end_to_end_latency += *latency; 

            

            // AP & UE generate the session key(put together to facilitate time computing)
            start = Instant::now();
            let ue_session_key = ECDHNISTP256::generate_shared_secret(&ue_private_num, &ap_public_num);
            let ap_session_key = ECDHNISTP256::generate_shared_secret(&ap_private_num, &ue_public_num);
            duration = start.elapsed();
            end_to_end_latency += duration;
            assert_eq!(ue_session_key, ap_session_key);

            accres += end_to_end_latency.as_millis();
        }

        writeln!(f_end_to_end_latency, "{:?}", accres/loopnum).unwrap();
        i += 1;
    }
}















pub fn test_handover() {

    
    let mut f_handover_latency = File::create("handover_latency.csv").unwrap();
    let mut handover_latency:Duration = Duration::new(0, 0);
    let mut time:Duration = Duration::new(0, 0);
    let mut vres: bool = false;
    let mut start = Instant::now(); 
    let mut duration = Duration::new(0, 0);
    let mut i = 0;

    for latency in SPACE_GROUND_LATENCY.iter() {

        
        println!("********     The {}th test begin !!!!      ********", i);
        println!("The space-ground latency is {:?}", latency);
        
        //*************** */
        // Handover process
        //*************** */

        println!("Handover process begin !!!!");
        let mut accres = 0;
        let loopnum = 10;
        for _ in 0..loopnum {
            handover_latency = Duration::new(0, 0);

            let new_ue_private_num = ECDHNISTP256::generate_private_key([2; 32]);
            let new_ue_public_num = ECDHNISTP256::generate_public_key(&new_ue_private_num);
    
    
            // compute the hash
            start = Instant::now();
            let hasher = Poseidon::new(BLS12_POSEIDON_PARAMS.clone());
            let i_b = hasher.hash(&new_ue_public_num.to_bytes().to_vec().to_field_elements().unwrap()).unwrap();
            let input3: Vec<u8> = vec![200,200,200,200,200]; // a random value for k2
            let ik2 = hasher.hash(&input3.to_field_elements().unwrap()).unwrap();
            let res2 = <Bls12PoseidonCrh as TwoToOneCRH>::evaluate(&(), &to_bytes!(i_b).unwrap(),&to_bytes!(ik2).unwrap()).unwrap();
            duration = start.elapsed();
            handover_latency += duration;
    
            // UE send the request to old SAP, add a space-ground latency
            handover_latency += *latency;
            // had better add an AES authenticator
    
            // Old SAP send the signature to new SAP, add a satellite-satellite latency
            // had better add an AES authenticator
            handover_latency += INTER_SAP_DELAY[0];
    
            // New SAP verify the signature and compute and sign the public key
            let (nap_sk, nap_vk) = ecdsa::generate_keypair();
            start = Instant::now();
            let new_ap_private_key = ECDHNISTP256::generate_private_key([12; 32]);
            let new_ap_public_key = ECDHNISTP256::generate_public_key(&new_ap_private_key);
            let n_siganature = ecdsa::sign_u8_type(&nap_sk, &new_ap_public_key.to_bytes());
            duration = start.elapsed();
            handover_latency += duration;
    
            // New SAP send the signature to UE
            handover_latency += *latency;
    
            // UE verify the signature and send the zk proof(k2) to new SAP
            start = Instant::now();
            let _is_valid = ecdsa::verify_signature(&nap_vk, &new_ap_public_key.to_bytes(), &n_siganature);
            duration = start.elapsed();
            handover_latency += duration; // ka proof generation is done in next several lines
    
            // UE send the zk proof to new SAP
            handover_latency += *latency;
    
            // New SAP verify the zk proof and compute the session key
            (vres,time) = zk_ka::runzkkatest(new_ue_public_num.to_bytes().to_vec());
            handover_latency += time;
    
            if vres {
                
            } else {
                println!("The ka proof is invalid");
            }
    
            start = Instant::now();
            let new_ap_session_key = ECDHNISTP256::generate_shared_secret(&new_ap_private_key, &new_ue_public_num);
            let new_ue_session_key = ECDHNISTP256::generate_shared_secret(&new_ue_private_num, &new_ap_public_key);
            duration = start.elapsed();
            handover_latency += duration;
    
            assert!(new_ap_session_key == new_ue_session_key);
            accres += handover_latency.as_millis();
        }

        writeln!(f_handover_latency, "{:?}", accres/loopnum).unwrap();

        i += 1;

    }

    

}

#[cfg(test)]
mod test{
    use crate::zk_akkh::test_aka;
    #[test]
    pub fn run_test_aka(){
        test_aka();
        assert!(true);
    }

    use crate::zk_akkh::test_handover;
    #[test]
    pub fn run_test_handover(){
        test_handover();
        assert!(true);
    }
}