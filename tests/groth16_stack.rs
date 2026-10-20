//! Smoke test for the arkworks stack: Groth16 over BN254 with a trivial
//! circuit ("I know x such that x * x = y"). It belongs to no story; it only
//! confirms that setup, proving and verification work with the pinned versions.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, fields::FieldVar};
use ark_relations::gr1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::UniformRand;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Private input `x`, public input `y`; constraint `x * x = y`.
#[derive(Clone)]
struct Square {
    x: Option<Fr>,
    y: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for Square {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let y = FpVar::new_input(cs.clone(), || {
            self.y.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let x = FpVar::new_witness(cs, || self.x.ok_or(SynthesisError::AssignmentMissing))?;
        x.square()?.enforce_equal(&y)
    }
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(42)
}

#[test]
fn stack_groth16_proves_and_verifies_x_squared() {
    let mut rng = rng();
    let x = Fr::rand(&mut rng);
    let y = x * x;

    let (pk, vk) = Groth16::<Bn254>::setup(Square { x: None, y: None }, &mut rng).expect("setup");
    let proof = Groth16::<Bn254>::prove(
        &pk,
        Square {
            x: Some(x),
            y: Some(y),
        },
        &mut rng,
    )
    .expect("prove");

    assert!(Groth16::<Bn254>::verify(&vk, &[y], &proof).expect("verify"));
}

#[test]
fn stack_groth16_rejects_wrong_public_input() {
    let mut rng = rng();
    let x = Fr::rand(&mut rng);
    let y = x * x;

    let (pk, vk) = Groth16::<Bn254>::setup(Square { x: None, y: None }, &mut rng).expect("setup");
    let proof = Groth16::<Bn254>::prove(
        &pk,
        Square {
            x: Some(x),
            y: Some(y),
        },
        &mut rng,
    )
    .expect("prove");

    let wrong_y = y + Fr::from(1u64);
    assert!(!Groth16::<Bn254>::verify(&vk, &[wrong_y], &proof).expect("verify"));
}

#[test]
fn stack_circuit_unsatisfied_with_wrong_witness() {
    let mut rng = rng();
    let x = Fr::rand(&mut rng);
    let y = x * x + Fr::from(1u64);

    let cs = ConstraintSystem::<Fr>::new_ref();
    Square {
        x: Some(x),
        y: Some(y),
    }
    .generate_constraints(cs.clone())
    .expect("synthesis");

    assert!(!cs.is_satisfied().expect("satisfiability check"));
}
