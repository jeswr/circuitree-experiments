use ark_bls12_377::{Bls12_377, Fr};
use ark_ff::fields::PrimeField;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::SynthesisError;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::prelude::StdRng;
use circuitree::utils::tests::remove_witness_from_input;
use circuitree::utils::*;
use circuitree::*;
use datalog::parsing::Question;
use datalog::reasoning::{Assertion, History, Reasoner, Ruleset};

type PS = Bls12_377;

const RULES_STR: &str = include_str!("cst.datalog");
const FACTS_STR: &str = include_str!("alice_cst.datalog");
const QUERY: &str = "?- ok(alice).";

fn mock_signature_gadget_prover<F: PrimeField>(
    history: &History<DATA>,
    max_args: usize,
) -> InputData<F> {
    InputData::from_history(&history, max_args)
}

fn mock_signature_gadget_verifier<F: PrimeField>(
    history: &History<DATA>,
    max_args: usize,
) -> InputData<F> {
    let id = InputData::from_history(&history, max_args);
    remove_witness_from_input(&id)
}

pub struct Prover {
    rules: Ruleset<String, DATA>,
    facts: Vec<Assertion<DATA>>,
    query: Question<String, DATA>,
    history: Option<History<DATA>>,
    input: Option<InputData<Fr>>,
    proving_key: Option<ProvingKey<PS>>,
}
impl Prover {
    fn new() -> Self {
        let rules = Ruleset::from_datalog(RULES_STR);
        let facts = <Vec<_>>::from_datalog(FACTS_STR);
        let query = Question::from_datalog(QUERY);
        Self {
            rules,
            facts,
            query,
            history: None,
            input: None,
            proving_key: None,
        }
    }

    fn setup(&mut self, v: &mut Verifier, rng: &mut StdRng) {
        let mut preliminary_reasoner = Reasoner::default();
        // Add rules to reasoner
        preliminary_reasoner.add_ruleset(self.rules.clone());
        // Add data to reasoner
        preliminary_reasoner.add_assertion_set(self.facts.clone());
        // Generate query
        // Reason
        let x = preliminary_reasoner.query(&self.query).unwrap();
        // Get history
        // Create arguments for proof
        let history = x.get_history();
        let max_args = get_max_arguments(&history, &self.rules);
        let input = mock_signature_gadget_prover(&history, max_args);

        // Create Verifier input
        let verifier_input = mock_signature_gadget_verifier(&history, max_args);
        let meta = IterationMetadata::from_history(&history, &self.rules);

        // Assign input and history
        self.history = Some(history);
        self.input = Some(input);

        self.proving_key = Some(v.setup(meta, verifier_input, rng).unwrap().0);
    }

    fn prove(self, rng: &mut StdRng) -> Proof<PS> {
        let prover = ReasonerProof {
            input: self.input.unwrap(),
            ptquery: self.query,
            rules: self.rules,
            allocation_data: AllocationData::History(self.history.unwrap()),
        };
        Groth16::<Bls12_377>::prove(&self.proving_key.unwrap(), prover, rng).unwrap()
    }
}

pub struct Verifier {
    rules: Ruleset<String, DATA>,
    query: Question<String, DATA>,
    pvk: Option<VerifyingKey<PS>>,
}
impl Verifier {
    fn new() -> Self {
        let rules = Ruleset::from_datalog(RULES_STR);
        let query = Question::from_datalog(QUERY);
        Self {
            rules,
            query,
            pvk: None,
        }
    }
    fn setup(
        &mut self,
        meta: IterationMetadata,
        input: InputData<Fr>,
        rng: &mut StdRng,
    ) -> Result<(ProvingKey<PS>, VerifyingKey<PS>), SynthesisError> {
        let v = ReasonerProof {
            input,
            ptquery: self.query.clone(),
            rules: self.rules.clone(),
            allocation_data: AllocationData::Metadata(meta),
        };
        Groth16::<Bls12_377>::setup(v, rng)
    }

    fn verify(&self, proof: Proof<PS>) -> Result<bool, SynthesisError> {
        Groth16::<Bls12_377>::verify(&self.pvk.as_ref().unwrap(), &[], &proof)
    }
}
fn run() {
    use ark_std::rand::SeedableRng;
    let mut rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(0u64);
    let mut prover = Prover::new();
    let mut verifier = Verifier::new();
    // Setup
    prover.setup(&mut verifier, &mut rng);
    verifier.pvk = Some(prover.proving_key.clone().unwrap().vk);
    // Prove
    let proof = prover.prove(&mut rng);

    // Print proof
    println!("Proof: {:?}", proof);

    // Verify
    let verification = verifier.verify(proof);
    match verification {
        Err(e) => println!("Error during verification: {}", e),
        Ok(true) => println!("CST ok!"),
        Ok(false) => println!("CST *not* ok!"),
    }
}

/// tests the run function
/// 
#[test]
fn test_run() {
    println!("Running test");
    run();
}
