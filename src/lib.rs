//! Provides an [`Actor`] and (de)serializable [`Token`] struct which support authenticating
//! Javascript Web Tokens with a custom payload. See [jwt.io](http://jwt.io) for more information
//! on the JWT spec.
//!
//! The provided [`Actor`] uses the
//! [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)
//! algorithm to sign tokens (using the [`ed25519_dalek`] crate).
//!
//! This library differs from other JWT implementations in that it allows for recursive [`Token`]s.
//!
//! Note that if the same `(host, actor)` pair is specified multiple times in the token chain,
//! only the latest is returned by [`Claims::get`].
//!
//! Example:
//! ```
//! # use std::collections::HashMap;
//! # use std::time::{Duration, SystemTime};
//! # use futures::executor::block_on;
//! # use async_trait::async_trait;
//! # use rjwt::*;
//!
//! # #[derive(Clone)]
//! struct Resolver {
//!     host: String,
//!     actors: HashMap<String, Actor<String>>,
//!     peers: HashMap<String, Resolver>,
//! }
//! // ...
//! # impl Resolver {
//! #    fn new(host: String, actor: Actor<String>, peers: Vec<Resolver>) -> Self {
//! #         let peers = peers.into_iter().map(|peer| (peer.host(), peer)).collect();
//! #         let actors = vec![(actor.id().to_string(), actor)].into_iter().collect();
//! #         Self { host, actors, peers }
//! #    }
//! # }
//!
//! const CLAIM: () = ();
//!
//! #[async_trait]
//! impl Resolve for Resolver {
//!     type Host = String;
//!     type ActorId = String;
//!     type Claims = ();
//!
//!     fn host(&self) -> String {
//!         self.host.clone()
//!     }
//!
//!     async fn resolve(
//!         &self,
//!         host: &Self::Host,
//!         actor_id: &Self::ActorId
//!     ) -> Result<Actor<Self::ActorId>> {
//!         if host == &self.host() {
//!             self.actors.get(actor_id).cloned().ok_or_else(|| Error::not_found())
//!         } else if let Some(peer) = self.peers.get(host) {
//!             peer.resolve(host, actor_id).await
//!         } else {
//!             Err(Error::not_found())
//!         }
//!     }
//! }
//!
//! let now = SystemTime::now();
//!
//! // Say that Bob is a user at example.com
//! let bobs_id = "bob".to_string();
//! let example_dot_com = "example.com".to_string();
//!
//! let actor_bob = Actor::new(bobs_id.clone());
//! let example = Resolver::new(example_dot_com.clone(), actor_bob.clone(), vec![]);
//!
//! // Bob makes a request through the retailer.com app.
//! let retail_app = Actor::new("app".to_string());
//! let retailer = Resolver::new(
//!     "retailer.com".to_string(), retail_app.clone(), vec![example.clone()]);
//!
//! // The retailer.com app makes a request to Bob's bank.
//! let bank_account = Actor::new("bank".to_string());
//! let bank = Resolver::new(
//!     "bank.com".to_string(), bank_account, vec![retailer.clone(), example]);
//!
//! // First, example.com issues a token to authenticate Bob.
//! let bobs_token = Token::new(
//!     example_dot_com.clone(),
//!     now,
//!     Duration::from_secs(30),
//!     actor_bob.id().to_string(),
//!     CLAIM);
//!
//! let bobs_token = actor_bob.sign_token(&bobs_token).unwrap();
//!
//! // Then, retailer.com consumes the token.
//! let (retailer_token, _) = block_on(
//!     retailer.consume(retail_app.id().to_string(), CLAIM, bobs_token, now)).unwrap();
//!
//! let retailer_token = retail_app.sign_token(&retailer_token).unwrap();
//!
//! // Finally, Bob's bank validates the token to verify that the request came from Bob.
//! let claims = block_on(bank.validate(&retailer_token, now)).unwrap();
//! assert_eq!(claims.get(&example_dot_com, &bobs_id).unwrap(), &CLAIM);
//! ```
//!

use std::fmt;
use std::pin::Pin;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures::Future;
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use signature::{Signer, Verifier};

pub use ed25519_dalek::{Keypair, PublicKey, Signature};

/// Trait which defines how to fetch the [`PublicKey`] given a host and actor ID.
#[async_trait]
pub trait Resolve: Send + Sync
where
    <Self::Host as FromStr>::Err: fmt::Display,
{
    type Host: fmt::Display + FromStr + Send + Sync;
    type ActorId: DeserializeOwned + PartialEq + Send + Sync;
    type Claims: DeserializeOwned + Send + Sync;

    /// The identity of the signing host.
    fn host(&self) -> Self::Host;

    /// Given a host and actor ID, return a corresponding [`Actor`].
    async fn resolve(
        &self,
        host: &Self::Host,
        actor_id: &Self::ActorId,
    ) -> Result<Actor<Self::ActorId>>;

    /// Validate the given encoded token and return a new [`Token`] which inherits from it,
    /// as well as the [`Claims`] of the validated token.
    ///
    /// The expiration time of the returned token is set equal to its parent.
    async fn consume(
        &self,
        actor_id: Self::ActorId,
        claims: Self::Claims,
        token: String,
        now: SystemTime,
    ) -> Result<(
        Token<Self::ActorId, Self::Claims>,
        Claims<Self::ActorId, Self::Claims>,
    )> {
        let parent_claims = self.validate(&token, now).await?;

        let iat = (now.duration_since(UNIX_EPOCH)).map_err(|e| Error::new(ErrorKind::Time, e))?;
        let token = Token {
            iss: self.host().to_string(),
            iat: iat.as_secs(),
            exp: parent_claims.exp,
            actor_id,
            custom: claims,
            inherit: Some(token),
        };

        Ok((token, parent_claims))
    }

    /// Validate the given encoded token and return its [`Claims`].
    fn validate<'a>(
        &'a self,
        encoded: &'a str,
        now: SystemTime,
    ) -> Pin<Box<dyn Future<Output = Result<Claims<Self::ActorId, Self::Claims>>> + Send + 'a>>
    {
        Box::pin(async move {
            let (message, signature) = token_signature(encoded)?;
            let token = decode_token(message)?;

            if token.is_expired(now)? {
                return Err(Error::new(ErrorKind::Time, "token is expired"));
            }

            let host = token
                .iss
                .parse()
                .map_err(|e| Error::new(ErrorKind::Format, e))?;

            let actor = self.resolve(&host, &token.actor_id).await?;

            if actor.id != token.actor_id {
                return Err(Error::new(
                    ErrorKind::Auth,
                    "attempted to use bearer token for different actor",
                ));
            } else if let Err(cause) = actor.public_key().verify(message.as_bytes(), &signature) {
                return Err(Error::new(
                    ErrorKind::Auth,
                    format!("invalid bearer token: {}", cause),
                ));
            }

            if let Some(parent) = token.inherit {
                let parent_claims = self.validate(&parent, now).await?;

                Ok(Claims::consume(
                    token.exp,
                    token.iss,
                    token.actor_id,
                    token.custom,
                    parent_claims,
                ))
            } else {
                Ok(Claims::new(
                    token.exp,
                    token.iss,
                    token.actor_id,
                    token.custom,
                ))
            }
        })
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

    /// A generic "not found" error.
    pub fn not_found() -> Self {
        Self {
            kind: ErrorKind::Fetch,
            message: "not found".to_string(),
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

/// All the claims of a recursive [`Token`].
#[derive(Clone, Debug)]
pub struct Claims<I, C> {
    exp: u64,
    host: String,
    actor_id: I,
    claims: C,
    inherit: Option<Box<Claims<I, C>>>,
}

impl<I: PartialEq, C> Claims<I, C> {
    fn new(exp: u64, host: String, actor_id: I, claims: C) -> Self {
        Self {
            exp,
            host,
            actor_id,
            claims,
            inherit: None,
        }
    }

    fn consume(exp: u64, host: String, actor_id: I, claims: C, parent: Self) -> Self {
        Self {
            exp,
            host,
            actor_id,
            claims,
            inherit: Some(Box::new(parent)),
        }
    }

    /// Get the most recent claim made by the specified [`Actor`].
    pub fn get(&self, host: &str, actor_id: &I) -> Option<&C> {
        if host == &self.host && actor_id == &self.actor_id {
            Some(&self.claims)
        } else if let Some(claims) = &self.inherit {
            claims.get(host, actor_id)
        } else {
            None
        }
    }
}

/// The Javascript Web Token wire format.
#[derive(Clone, Deserialize, Serialize)]
pub struct Token<I, C> {
    iss: String,
    iat: u64,
    exp: u64,
    actor_id: I,
    custom: C,
    inherit: Option<String>,
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
            inherit: None,
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
    pub fn is_expired(&self, now: SystemTime) -> Result<bool> {
        let iat = UNIX_EPOCH + Duration::from_secs(self.iat);
        let exp = UNIX_EPOCH + Duration::from_secs(self.exp);
        let ttl = exp
            .duration_since(iat)
            .map_err(|e| Error::new(ErrorKind::Time, e))?;

        match now.duration_since(iat) {
            Ok(elapsed) => Ok(elapsed > ttl),
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
/// *IMPORTANT NOTE*: for security reasons, although `Actor` implements `Clone`, its secret key will
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
