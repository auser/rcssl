use rcgen::SignatureAlgorithm;

pub fn get_algorithm(algorithm: &str) -> &'static SignatureAlgorithm {
    match algorithm {
        "RSA256" => &rcgen::PKCS_RSA_SHA256,
        "RSA384" => &rcgen::PKCS_RSA_SHA384,
        "RSA512" => &rcgen::PKCS_RSA_SHA512,
        "ECDSA_P256_SHA256" => &rcgen::PKCS_ECDSA_P256_SHA256,
        "ECDSA_P384_SHA384" => &rcgen::PKCS_ECDSA_P384_SHA384,
        "ED25519" => &rcgen::PKCS_ED25519,
        _ => panic!("Unknown algorithm: {}", algorithm),
    }
}
