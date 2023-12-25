use crate::protocol::{EPk, ESk, SymKey, XAEADNonce, SessionId, HandshakeState};

use rosenpass_cipher_traits::Kem;
use rosenpass_ciphers::hash_domain::SecretHashDomainNamespace;
use rosenpass_ciphers::kem::{EphemeralKem, StaticKem};
use rosenpass_ciphers::KEY_LEN;
use rosenpass_secret_memory::Secret;

use std::collections::hash_map::HashMap;
use std::rc::Rc;

#[cfg(feature = "test_vectors")]
#[derive(Debug)]
pub struct TestHarness {
    pub test_vector: Option<Rc<TestVector>>
}

#[cfg(feature = "test_vectors")]
impl TestHarness {
    pub fn new() -> Self {
        Self {
            test_vector: None
        }
    }

    pub fn overwrite_nonce(&self, n: &mut XAEADNonce) {
        if let Some(test_vector) = &self.test_vector {
            *n = test_vector.biscuit_nonce;
        }
    }

    pub fn overwrite_sidi(&self, sidi: &mut SessionId) {
        if let Some(test_vector) = &self.test_vector {
            sidi.clone_from(&test_vector.sidi);
        }
    }

    pub fn overwrite_ephemeral_keys(&self, eski: &mut ESk, epki: &mut EPk) {
        if let Some(test_vector) = &self.test_vector {
            eski.clone_from(&test_vector.eski);
            epki.clone_from(&test_vector.epki);
        }
    }

    pub fn overwrite_sctr_and_mix(&self, core: &mut HandshakeState, sctr: &mut [u8], spkt: &[u8]) {
        if let Some(test_vector) = &self.test_vector {
            sctr.copy_from_slice(test_vector.sctr.as_ref());
            core.mix(spkt).unwrap().mix(test_vector.shk1.secret()).unwrap().mix(sctr).unwrap();
        } else {
            core.encaps_and_mix::<StaticKem, { StaticKem::SHK_LEN }>(sctr, spkt).unwrap();
        }
    }

    pub fn overwrite_sidr(&self, sidr: &mut SessionId) {
        if let Some(test_vector) = &self.test_vector {
            sidr.clone_from(&test_vector.sidr);
        }
    }

    pub fn overwrite_ecti_and_mix(&self, core: &mut HandshakeState, ecti: &mut [u8], epki: &[u8]) {
        if let Some(test_vector) = &self.test_vector {
            ecti.copy_from_slice(test_vector.ecti.as_ref());
            core.mix(epki).unwrap().mix(test_vector.shk2.secret()).unwrap().mix(ecti).unwrap();
        } else {
            core.encaps_and_mix::<EphemeralKem, { EphemeralKem::SHK_LEN }>(ecti, epki).unwrap();
        }
    }

    pub fn overwrite_scti_and_mix(&self, core: &mut HandshakeState, scti: &mut [u8], spkt: &[u8]) {
        if let Some(test_vector) = &self.test_vector {
            scti.copy_from_slice(test_vector.scti.as_ref());
            core.mix(spkt).unwrap().mix(test_vector.shk3.secret()).unwrap().mix(scti).unwrap();
        } else {
            core.encaps_and_mix::<StaticKem, { StaticKem::SHK_LEN }>(scti, spkt).unwrap();
        }
    }

    pub fn check_chaining_key(&self, ck: &SecretHashDomainNamespace, handshake_step_id: &str) {
        if let Some(test_vector) = &self.test_vector {
            let ck_secret = ck.clone().danger_into_secret();

            // TOOD: should it be possible for keys to be missing?
            if let Some(expected_chaining_key) = test_vector.expected_chaining_keys.get(handshake_step_id) {
                assert_eq!(ck_secret.secret(), expected_chaining_key.secret());
            }
        }
    }

    pub fn check_osk(&self, osk: SymKey) {
        if let Some(test_vector) = &self.test_vector {
            assert_eq!(osk.secret(), test_vector.expected_osk.secret());
        }
    }
}

#[cfg(feature = "test_vectors")]
/// Struct representing a test vector
///
/// Holds custom input and corresponding expected output values
#[derive(Clone, Debug)]
pub struct TestVector {
    // Custom Input Values
    pub eski: ESk,
    pub epki: EPk,
    pub sidi: SessionId,
    pub sidr: SessionId,
    pub biscuit_nonce: XAEADNonce,

    pub shk1: Secret<{ StaticKem::SHK_LEN }>,
    pub sctr: [u8; StaticKem::CT_LEN],

    pub shk2: Secret<{ EphemeralKem::SHK_LEN }>,
    pub ecti: [u8; EphemeralKem::CT_LEN],

    pub shk3: Secret<{ StaticKem::SHK_LEN }>,
    pub scti: [u8; StaticKem::CT_LEN],

    // Expected intermediate chaining keys
    // e.g., expected_chaining_keys["IHI4"] contains expected chaining key after processing "IHI4"
    pub expected_chaining_keys: HashMap<String, Secret<KEY_LEN>>,

    // Expected output shared key
    pub expected_osk: SymKey,
}

#[cfg(feature = "test_vectors")]
impl TestVector {
    pub fn new(
        eski: ESk,
        epki: EPk,
        sidi: SessionId,
        sidr: SessionId,
        shk1: Secret<{ StaticKem::SHK_LEN }>,
        sctr: [u8; StaticKem::CT_LEN],
        shk2: Secret<{ EphemeralKem::SHK_LEN }>,
        ecti: [u8; EphemeralKem::CT_LEN],
        shk3: Secret<{ StaticKem::SHK_LEN }>,
        scti: [u8; StaticKem::CT_LEN],
        biscuit_nonce: XAEADNonce,
        expected_chaining_keys: HashMap<String, Secret<KEY_LEN>>,
        expected_osk: SymKey) -> Self {
        Self {
            eski,
            epki,
            sidi,
            sidr,
            shk1,
            sctr,
            shk2,
            ecti,
            shk3,
            scti,
            biscuit_nonce,
            expected_chaining_keys,
            expected_osk
        }
    }
}
