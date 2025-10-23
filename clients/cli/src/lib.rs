use blake2::Blake2s256;
use jni::{ objects::{ JClass, JString }, sys::{ jint, jstring }, JNIEnv };
use nexus_sdk::{ stwo::seq::{ Proof, Stwo }, Local, Prover };
use postcard::to_allocvec;
use sha3::{ Digest, Keccak256 };

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_htmk_Nexus_init(
    mut env: JNIEnv,
    _class: JClass,
    input: JString
) -> jstring {
    let input: String = env.get_string(&input).unwrap().into();
    let mut hash = Blake2s256::new();
    hash.update(&input);
    let code = hash.finalize();
    let output = format!("Hello from Rust, {}!", input);
    let output = format!("{:x} {}", code, output);
    env.new_string(output).unwrap().into_raw()
}

const ELF_PROVER: &[u8; 104004] = include_bytes!("../assets/fib_input_initial");

pub fn create_fib_prover() -> Stwo<Local> {
    Stwo::<Local>::new_from_bytes(ELF_PROVER).unwrap()
}

pub fn generate_proof_hash(proof: &Proof) -> String {
    let proof_bytes = postcard::to_allocvec(proof).expect("Failed to serialize proof");
    format!("{:x}", Keccak256::digest(&proof_bytes))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_htmk_Nexus_fib(
    mut env: JNIEnv,
    _class: JClass,
    has_proof: jint,
    input: JString
) -> jstring {
    let inputs: String = env.get_string(&input).unwrap().into();
    let inputs: (u32, u32, u32) = serde_json::from_str(&inputs).unwrap();

    let stwo = create_fib_prover();
    let (view, proof) = stwo.prove_with_input::<(), (u32, u32, u32)>(&(), &inputs).unwrap();

    if has_proof == 1 {
        let bytes = to_allocvec(&proof).unwrap();
        env.new_string(std::str::from_utf8(&bytes).unwrap()).unwrap().into_raw()
    } else {
        let proof_hash = generate_proof_hash(&proof);
        env.new_string(&proof_hash).unwrap().into_raw()
    }
}
// cargo ndk --target arm64-v8a  -o '/Users/hemh/Desktop/test/gameclick/app/src/main/jniLibs'  build --release

// /Users/hemh/Library/Android/sdk/ndk/28.0.12674087/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-objdump \
// -d /Users/hemh/Desktop/test/gameclick/app/src/main/jniLibs/arm64-v8a/libnexus_network.so > disasm.txt