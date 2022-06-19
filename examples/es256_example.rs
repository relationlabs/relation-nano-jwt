use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use nano_jwt::{algo::ES256, ClaimErrorKind, Jwt, JwtClaims, JwtError, TimeOptions};

/// Custom claims (NOTE: add more fields according real use case)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CustomClaims {
    #[serde(rename = "sub")]
    pub subject: String,
    pub name: String,
    #[serde(default)]
    pub admin: bool,
}

fn run_example(jwt: &Jwt<ES256>) {
    let custom = CustomClaims {
        subject: "sub1".to_string(),
        name: "name1".to_string(),
        admin: false,
    };

    // check token sign & verification succeeded
    let expiration = Duration::seconds(600);
    let time_options = TimeOptions::new(Duration::seconds(5), Utc::now);
    let claims = JwtClaims::new(custom.clone()).with_expiration_and_issuance(&time_options, expiration);
    let result = jwt.sign(&claims);
    let token = result.unwrap();
    println!("JWT token signed: {}", &token);
    let result = jwt.verify::<CustomClaims, _>(&token, &time_options);
    assert!(result.is_ok());
    assert_eq!(custom, result.as_ref().unwrap().claims.custom);
    println!("JWT token verified: {:?}", &result);

    // check token expiration
    let expiration = Duration::seconds(1);
    let claims = JwtClaims::new(custom.clone()).with_expiration_and_issuance(&time_options, expiration);
    let result = jwt.sign(&claims);
    let token = result.unwrap();
    println!("Waiting 6s for token to expire...");
    std::thread::sleep(std::time::Duration::from_secs(6));
    let result = jwt.verify::<CustomClaims, _>(&token, &time_options);
    let err = result.as_ref().err().unwrap();
    assert!(err.is_token_expired());
    assert!(matches!(err, JwtError::InvalidClaims(ClaimErrorKind::TokenExpired)));
    println!("JWT token expiration expected: {:?}", &result);
}

fn main() {
    // PEM-encoded SEC 1 private key
    let private_key_sec1_pem = include_str!("keys/es256_private.pem");
    let es256 = ES256::from_sec1_pem(private_key_sec1_pem);
    let jwt = Jwt::new(es256);
    println!("1. PEM-encoded SEC 1");
    run_example(&jwt);
    println!();

    // PEM-encoded PKCS#8 private key (same key different format)
    let private_key_pkcs8_pem = include_str!("keys/es256_private_pkcs8.pem");
    let es256 = ES256::from_pkcs8_pem(private_key_pkcs8_pem);
    let jwt = Jwt::new(es256);
    println!("2. PEM-encoded PKCS#8");
    run_example(&jwt);
    println!();

    let jwk = include_str!("keys/es256_jwk_private.json");
    let es256 = ES256::from_jwk(jwk);
    let jwt = Jwt::new(es256);
    println!("3. JWK");
    run_example(&jwt);
    println!();
}