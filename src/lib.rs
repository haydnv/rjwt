//! Provides an [`Actor`] and (de)serializable [`Token`] struct which support authenticating
//! Javascript Web Tokens with a custom payload. See [jwt.io](http://jwt.io) for more information
//! on the JWT spec.
//!
//! The provided [`Actor`] uses the
//! [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
//! algorithm to sign tokens (using the [`ed25519_dalek`] crate).
//!
//! Example:
//! ```
//! # use std::collections::HashMap;
//! # use std::time::{Duration, SystemTime};
//! # use futures::executor::block_on;
//! # use async_trait::async_trait;
//! # use rjwt::*;
//!
//! struct Resolver {
//!     actors: HashMap<String, Actor<String>>,
//! }
//!
//! #[async_trait]
//! impl Resolve for Resolver {
//!     type Host = String;
//!     type ActorId = String;
//!     type Claims = ();
//!
//!     async fn resolve(
//!         &self,
//!         _host: &Self::Host,
//!         actor_id: &Self::ActorId
//!     ) -> Result<Actor<Self::ActorId>> {
//!         self
//!             .actors
//!             .get(actor_id)
//!             .cloned()
//!             .ok_or_else(|| Error::new(ErrorKind::Fetch, actor_id))
//!     }
//! }
//!
//! let actor = Actor::new("actor1".to_string());
//! let resolver = Resolver {
//!     actors: vec![("actor1".to_string(), actor.clone())].into_iter().collect()
//! };
//!
//! let token = Token::new(
//!     "example.com".to_string(),
//!     SystemTime::now(),
//!     Duration::from_secs(30),
//!     actor.id().to_string(),
//!     ());
//!
//! let encoded = actor.sign_token(&token).unwrap();
//! let decoded = block_on(resolver.validate(&encoded)).unwrap();
//! assert_eq!(token, decoded);
//! ```
//!

use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use signature::{Signer, Verifier};

pub use ed25519_dalek::{Keypair, PublicKey, Signature};

#[async_trait]
pub trait Resolve
where
    <Self::Host as FromStr>::Err: fmt::Display,
{
    type Host: FromStr + Send + Sync;
    type ActorId: DeserializeOwned + PartialEq + Send + Sync;
    type Claims: DeserializeOwned + Send + Sync;

    async fn resolve(
        &self,
        host: &Self::Host,
        actor_id: &Self::ActorId,
    ) -> Result<Actor<Self::ActorId>>;

    async fn validate(
        &self,
        encoded: &str,
    ) -> std::result::Result<Token<Self::ActorId, Self::Claims>, Error> {
        let (message, signature) = token_signature(encoded)?;
        let token = decode_token(message)?;

        let host = token
            .iss
            .parse()
            .map_err(|e| Error::new(ErrorKind::Format, e))?;

        let actor = self.resolve(&host, &token.actor_id).await?;

        if actor.id != token.actor_id {
            Err(Error::new(
                ErrorKind::Auth,
                "attempted to use bearer token for different actor",
            ))
        } else if actor
            .public_key()
            .verify(message.as_bytes(), &signature)
            .is_err()
        {
            Err(Error::new(ErrorKind::Auth, "invalid bearer token"))
        } else {
            Ok(token)
        }
    }
}

/// The type of error encountered.
/// `Auth` means that the token signature failed validation.
/// `Fetch` means that there was an error fetching the public key of the actor to validate.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ErrorKind {
    Base64,
    Fetch,
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
            Self::Fetch => "key fetch",
            Self::Format => "token format",
            Self::Json => "json format",
            Self::Time => "time",
        })
    }
}

/// An error encountered while handling a [`Token`].
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    pub fn new<M: fmt::Display>(kind: ErrorKind, message: M) -> Self {
        Self {
            kind,
            message: message.to_string(),
        }
    }

    /// The [`ErrorKind`] of this error.
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

/// The result of a [`Token`] operation.
pub type Result<T> = std::result::Result<T, Error>;

/// The Javascript Web Token wire format.
#[derive(Clone, Deserialize, Serialize)]
pub struct Token<I, C> {
    iss: String,
    iat: u64,
    exp: u64,
    actor_id: I,
    custom: C,
    inherit: Vec<String>
}

impl<I: Eq, C: Eq> Eq for Token<I, C> {}

impl<I: PartialEq, C: PartialEq> PartialEq for Token<I, C> {
    fn eq(&self, other: &Self) -> bool {
        self.iss == other.iss
            && self.iat == other.iat
            && self.exp == other.exp
            && self.actor_id == other.actor_id
            && self.custom == other.custom
            && self.inherit == other.inherit
    }
}

impl<I, C> Token<I, C> {
    /// Create a new (unsigned) token.
    pub fn new(iss: String, iat: SystemTime, ttl: Duration, actor_id: I, claims: C) -> Self {
        let iat = iat.duration_since(UNIX_EPOCH).unwrap();
        let exp = iat + ttl;

        Self {
            iss,
            iat: iat.as_secs(),
            exp: exp.as_secs(),
            actor_id,
            custom: claims,
            inherit: vec![]
        }
    }

    /// The claimed issuer of this token.
    pub fn issuer(&'_ self) -> &'_ str {
        &self.iss
    }

    /// The actor to whom this token claims to belong.
    pub fn actor_id(&'_ self) -> &'_ I {
        &self.actor_id
    }

    /// Returns `Ok(false)` if the token is expired, `Err` if it contains nonsensical time data
    /// (like a negative timestamp or a future issue time), or `Ok(true)` if the token could
    /// be valid at the given moment.
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

    /// The custom claims field of this token.
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

impl<I: fmt::Display, C> fmt::Debug for Token<I, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<I: fmt::Display, C> fmt::Display for Token<I, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "JWT token claiming Actor {} at host {}",
            self.actor_id, self.iss
        )
    }
}

enum Key {
    Public(PublicKey),
    Secret(Keypair),
}

/// An actor with an identifier of type `T` and an ECDSA keypair used to sign tokens.
///
/// *IMPORTANT NOTE*: for security reasons, although `Actor` implements `Clone`, a private key will
/// NOT be cloned. For example:
/// ```
/// # use rjwt::Actor;
/// let actor = Actor::<String>::new("id".to_string()); // this has a new secret key
/// let cloned = actor.clone(); // this does NOT have a secret key, only a public key
/// ```
pub struct Actor<I> {
    id: I,
    key: Key,
}

impl<I> Actor<I> {
    /// Generate a new ECDSA keypair.
    pub fn new_keypair() -> Keypair {
        let mut rng = OsRng {};
        Keypair::generate(&mut rng)
    }

    /// Return an `Actor` with a newly-generated keypair.
    pub fn new(id: I) -> Self {
        Actor {
            id,
            key: Key::Secret(Self::new_keypair()),
        }
    }

    /// Return an `Actor` with the given keypair, or an error if the keypair is invalid.
    pub fn with_keypair(id: I, public_key: &[u8], secret: &[u8]) -> Result<Self> {
        let keypair = Keypair::from_bytes(&[secret, public_key].concat())
            .map_err(|e| Error::new(ErrorKind::Auth, e))?;

        Ok(Self {
            id,
            key: Key::Secret(keypair),
        })
    }

    /// Return an `Actor` with the given public key, or an error if the key is invalid.
    pub fn with_public_key(id: I, public_key: &[u8]) -> Result<Self> {
        let key = PublicKey::from_bytes(public_key).map_err(|e| Error::new(ErrorKind::Auth, e))?;
        Ok(Self {
            id,
            key: Key::Public(key),
        })
    }

    /// The identifier of this actor.
    pub fn id(&'_ self) -> &'_ I {
        &self.id
    }

    /// The public key of this actor, which a client can use to verify a signature.
    pub fn public_key(&'_ self) -> &'_ PublicKey {
        match &self.key {
            Key::Public(public) => public,
            Key::Secret(secret) => &secret.public,
        }
    }

    /// Encode and sign the given token.
    pub fn sign_token<C: Serialize>(&self, token: &Token<I, C>) -> Result<String>
    where
        I: Serialize,
    {
        let keypair = if let Key::Secret(keypair) = &self.key {
            keypair
        } else {
            return Err(Error::new(
                ErrorKind::Auth,
                "cannot sign a token without a private key",
            ));
        };

        let header = base64_json_encode(&TokenHeader::default())?;
        let claims = base64_json_encode(&token)?;

        let signature = base64::encode(
            &keypair
                .sign(format!("{}.{}", header, claims).as_bytes())
                .to_bytes()[..],
        );

        Ok(format!("{}.{}.{}", header, claims, signature))
    }
}

impl<I: Clone> Clone for Actor<I> {
    fn clone(&self) -> Self {
        let key = self.public_key().clone();
        Actor {
            key: Key::Public(key),
            id: self.id.clone(),
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

fn token_signature(encoded: &str) -> Result<(&str, Signature)> {
    if encoded.ends_with('.') {
        return Err(Error::new(
            ErrorKind::Format,
            "encoded token cannot end with .",
        ));
    }

    let i = encoded
        .rfind('.')
        .ok_or_else(|| Error::new(ErrorKind::Format, format!("invalid token: {}", encoded)))?;

    let message = &encoded[..i];

    let signature =
        base64::decode(&encoded[(i + 1)..]).map_err(|e| Error::new(ErrorKind::Base64, e))?;

    let signature =
        signature::Signature::from_bytes(&signature).map_err(|e| Error::new(ErrorKind::Auth, e))?;

    Ok((message, signature))
}

fn decode_token<I: DeserializeOwned, C: DeserializeOwned>(encoded: &str) -> Result<Token<I, C>> {
    let i = encoded
        .find('.')
        .ok_or_else(|| Error::new(ErrorKind::Format, format!("invalid token: {}", encoded)))?;

    let header = base64_decode(&encoded[..i])?;
    let header: TokenHeader =
        serde_json::from_slice(&header).map_err(|e| Error::new(ErrorKind::Json, e))?;

    if header != TokenHeader::default() {
        return Err(Error::new(
            ErrorKind::Format,
            "Unsupported bearer token type",
        ));
    }

    let token = base64_decode(&encoded[(i + 1)..])?;
    serde_json::from_slice(&token).map_err(|e| Error::new(ErrorKind::Json, e))
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

#[cfg(test)]
mod tests {
    const SIZE_LIMIT: usize = 8000; // max HTTP header size
    use super::*;

    #[test]
    fn test_format() {
        let actor = Actor::new("actor".to_string());
        let token = Token::new(
            "example.com".to_string(),
            SystemTime::now(),
            Duration::from_secs(30),
            actor.id().to_string(),
            (),
        );

        let encoded = actor.sign_token(&token).unwrap();
        let (message, _) = token_signature(&encoded).unwrap();
        assert!(encoded.starts_with(message));

        println!("length {}", encoded.len());
        assert!(encoded.len() < SIZE_LIMIT);
    }
}
