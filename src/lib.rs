use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use serde::de::{DeserializeOwned, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use signature::{Signature, Signer, Verifier};

pub use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature as ECSignature};
pub use url::Url;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ErrorKind {
    Base64,
    Format,
    Json,
    Auth,
    Time,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::Auth => "authentication",
            Self::Base64 => "base64 format",
            Self::Format => "token format",
            Self::Json => "json format",
            Self::Time => "time",
        })
    }
}

pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    fn new<M: fmt::Display>(kind: ErrorKind, message: M) -> Self {
        Self {
            kind,
            message: message.to_string(),
        }
    }

    pub fn kind(&'_ self) -> ErrorKind {
        self.kind
    }
}

impl std::error::Error for Error {}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} error: {}", self.kind, self.message)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Deserialize, Serialize)]
pub struct Token<I, S> {
    #[serde(deserialize_with = "deserialize_url", serialize_with = "serialize_url")]
    iss: Url,
    iat: u64,
    exp: u64,
    actor_id: I,
    custom: S,
}

impl<I, C> Token<I, C> {
    pub fn new(iss: Url, iat: SystemTime, ttl: Duration, actor_id: I, claims: C) -> Self {
        let iat = iat.duration_since(UNIX_EPOCH).unwrap();
        let exp = iat + ttl;

        Self {
            iss,
            iat: iat.as_secs(),
            exp: exp.as_secs(),
            actor_id,
            custom: claims,
        }
    }

    pub fn issuer(&'_ self) -> &'_ Url {
        &self.iss
    }

    pub fn actor_id(&'_ self) -> &'_ I {
        &self.actor_id
    }

    pub fn expired(&self, now: SystemTime) -> Result<bool> {
        let iat = UNIX_EPOCH + Duration::from_secs(self.iat);
        let exp = UNIX_EPOCH + Duration::from_secs(self.exp);
        let ttl = exp
            .duration_since(iat)
            .map_err(|e| Error::new(ErrorKind::Time, e))?;

        match now.duration_since(iat) {
            Ok(elapsed) => Ok(elapsed <= ttl),
            Err(cause) => Err(Error::new(ErrorKind::Time, cause)),
        }
    }

    pub fn claims(&'_ self) -> &'_ C {
        &self.custom
    }
}

impl<I: DeserializeOwned, C: DeserializeOwned> FromStr for Token<I, C> {
    type Err = Error;

    fn from_str(token: &str) -> Result<Self> {
        let token: Vec<&str> = token.split('.').collect();
        if token.len() != 3 {
            return Err(Error::new(
                ErrorKind::Format,
                "Expected a bearer token in the format '<header>.<claims>.<data>'",
            ));
        }

        let token = base64_decode(token[1])?;
        json_decode(&token)
    }
}

impl<I: fmt::Display, C> fmt::Display for Token<I, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Actor {} at host {}", self.actor_id, self.iss)
    }
}

pub struct Actor<I> {
    id: I,
    keypair: Keypair,
}

impl<I: Eq + DeserializeOwned + Serialize> Actor<I> {
    pub fn new_keypair() -> Keypair {
        let mut rng = OsRng {};
        Keypair::generate(&mut rng)
    }

    pub fn new(id: I) -> Self {
        Actor {
            id,
            keypair: Self::new_keypair(),
        }
    }

    pub fn with_keypair(id: I, keypair: Keypair) -> Self {
        Self { id, keypair }
    }

    pub fn public_key(&'_ self) -> &'_ PublicKey {
        &self.keypair.public
    }

    pub fn sign_token<C: Serialize>(&self, token: &Token<I, C>) -> Result<String> {
        let header = base64_json_encode(&TokenHeader::default())?;
        let claims = base64_json_encode(&token)?;

        let signature = base64::encode(
            &self
                .keypair
                .sign(format!("{}.{}", header, claims).as_bytes())
                .to_bytes()[..],
        );

        Ok(format!("{}.{}.{}", header, claims, signature))
    }

    pub fn validate<C: DeserializeOwned>(&self, encoded: &str) -> Result<Token<I, C>> {
        let mut encoded: Vec<&str> = encoded.split('.').collect();
        if encoded.len() != 3 {
            return Err(Error::new(
                ErrorKind::Format,
                "Expected bearer token in the format '<header>.<claims>.<data>'",
            ));
        }

        let message = format!("{}.{}", encoded[0], encoded[1]);
        let signature =
            base64::decode(encoded.pop().unwrap()).map_err(|e| Error::new(ErrorKind::Base64, e))?;
        let signature =
            ECSignature::from_bytes(&signature).map_err(|e| Error::new(ErrorKind::Auth, e))?;

        let token = encoded.pop().unwrap();
        let token = base64::decode(token).map_err(|e| Error::new(ErrorKind::Base64, e))?;
        let token: Token<I, C> =
            serde_json::from_slice(&token).map_err(|e| Error::new(ErrorKind::Json, e))?;

        if token.actor_id != self.id {
            return Err(Error::new(
                ErrorKind::Auth,
                "Attempted to use a bearer token for a different actor",
            ));
        }

        let header = encoded.pop().unwrap();
        let header = base64::decode(header).map_err(|e| Error::new(ErrorKind::Base64, e))?;
        let header: TokenHeader =
            serde_json::from_slice(&header).map_err(|e| Error::new(ErrorKind::Json, e))?;

        if header != TokenHeader::default() {
            Err(Error::new(
                ErrorKind::Format,
                "Unsupported bearer token type",
            ))
        } else if self
            .public_key()
            .verify(message.as_bytes(), &signature)
            .is_err()
        {
            Err(Error::new(ErrorKind::Auth, "Invalid bearer token"))
        } else {
            Ok(token)
        }
    }
}

#[derive(Eq, PartialEq, Deserialize, Serialize)]
struct TokenHeader {
    alg: String,
    typ: String,
}

impl Default for TokenHeader {
    fn default() -> TokenHeader {
        TokenHeader {
            alg: "ES256".into(),
            typ: "JWT".into(),
        }
    }
}

fn base64_decode(encoded: &str) -> Result<Vec<u8>> {
    base64::decode(encoded).map_err(|e| Error::new(ErrorKind::Base64, e))
}

fn json_decode<'de, T: Deserialize<'de>>(encoded: &'de [u8]) -> Result<T> {
    serde_json::from_slice(encoded).map_err(|e| Error::new(ErrorKind::Json, e))
}

fn base64_json_encode<T: Serialize>(data: &T) -> Result<String> {
    let as_str = serde_json::to_string(data).map_err(|e| Error::new(ErrorKind::Json, e))?;
    Ok(base64::encode(&as_str))
}

fn deserialize_url<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Url, D::Error> {
    let as_str = String::deserialize(d)?;
    Url::from_str(&as_str).map_err(serde::de::Error::custom)
}

fn serialize_url<S: Serializer>(url: &Url, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&url.to_string())
}
