extern crate rand_os;
extern crate x25519_dalek;

use rand_os::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};
use log::*;

fn main() {
    pretty_env_logger::init();
    // Perform an ephemeral elliptic curve Diffie-Hellman key exchange

    // Alice creates her key pair
    let mut alice_csprng = OsRng::new().unwrap();
    let alice_secret = EphemeralSecret::new(&mut alice_csprng);
    let alice_public = PublicKey::from(&alice_secret);
    info!("Alice's public key: {:?}", hex::encode(alice_public.as_bytes()));

    // Bob does the same
    let mut bob_csprng = OsRng::new().unwrap();
    let bob_secret = EphemeralSecret::new(&mut bob_csprng);
    let bob_public = PublicKey::from(&bob_secret);
    info!("Bob's public key: {:?}", hex::encode(bob_public.as_bytes()));

    // Now Alice and Bob compute their shared secret
    let alice_shared_secret = alice_secret.diffie_hellman(&bob_public);
    let bob_shared_secret = bob_secret.diffie_hellman(&alice_public);

    // These secrets are the same
    assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
    info!("Persistent shared secret: {:?}", hex::encode(alice_shared_secret.as_bytes()));

    // Now Alice and Bob can use their shared secret to encrypt their communications
}
