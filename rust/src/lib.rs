//! Provides an [`Actor`] and (de)serializable [`Token`] struct which support authenticating
//! JSON Web Tokens with a custom payload. See [jwt.io](http://jwt.io) for more information
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
//! # use async_trait::async_trait;
//! # use futures::executor::block_on;
//! use rjwt::*;
//!
//! #[derive(Clone)]
//! struct Resolver {
//!     hostname: String,
//!     actors: HashMap<String, Actor<String>>,
//!     peers: Vec<Self>,
//! }
//! // ...
//! # impl Resolver {
//! #    fn new<A: IntoIterator<Item = Actor<String>>>(hostname: String, actors: A, peers: Vec<Self>) -> Self {
//! #        Self { hostname, actors: actors.into_iter().map(|a| (a.id().clone(), a)).collect(), peers }
//! #    }
//! # }
//!
//! #[async_trait]
//! impl Resolve for Resolver {
//!     type HostId = String;
//!     type ActorId = String;
//!     type Claims = String;
//!
//!     async fn resolve(&self, host: &Self::HostId, actor_id: &Self::ActorId) -> Result<Actor<Self::ActorId>, Error> {
//!         if host == &self.hostname {
//!             self.actors.get(actor_id).cloned().ok_or_else(|| Error::not_found(actor_id))
//!         } else if let Some(peer) = self.peers.iter().filter(|p| &p.hostname == host).next() {
//!             peer.resolve(host, actor_id).await
//!         } else {
//!             Err(Error::not_found(host))
//!         }
//!     }
//! }
//!
//! let now = SystemTime::now();
//!
//! // Say that Bob is a user on example.com.
//! let bobs_id = "bob".to_string();
//! let example_dot_com = "example.com".to_string();
//!
//! let actor_bob = Actor::new(bobs_id.clone());
//! let example = Resolver::new(example_dot_com.clone(), [actor_bob.clone()], vec![]);
//!
//! // Bob makes a request through the retailer.com app.
//! let retail_app = Actor::new("app".to_string());
//! let retailer = Resolver::new(
//!     "retailer.com".to_string(),
//!     [retail_app.clone()],
//!     vec![example.clone()]);
//!
//! // The retailer.com app makes a request to Bob's bank.
//! let bank_account = Actor::new("bank".to_string());
//! let bank = Resolver::new(
//!     "bank.com".to_string(),
//!     [bank_account.clone()],
//!     vec![example, retailer.clone()]);
//!
//! // First, example.com issues a token to authenticate Bob.
//! let bobs_claim = String::from("I am Bob and retailer.com may debit my bank.com account");
//! let bobs_token = Token::new(
//!     example_dot_com.clone(),
//!     now,
//!     Duration::from_secs(30),
//!     actor_bob.id().to_string(),
//!     bobs_claim);
//!
//! let bobs_token_signed = actor_bob.sign_token(&bobs_token).expect("signed token");
//!
//! // Then, retailer.com validates the token
//! let claims = block_on(retailer.validate(&bobs_token_signed, now)).expect("claims");
//! assert!(claims.get(&example_dot_com, &bobs_id).expect("claim").starts_with("I am Bob"));
//!
//! let retailer_claim = String::from("Bob spent $1 on retailer.com");
//! let retailer_token = Token::consume(
//!         bobs_token_signed,
//!         now,
//!         Duration::from_secs(3),
//!         "retailer.com".to_string(),
//!         "app".to_string(),
//!         retailer_claim
//!     ).expect("token");
//!
//! let retailer_token = retail_app.sign_token(&retailer_token).expect("signed token");
//!
//! // Finally, Bob's bank validates the token to verify that the request came from Bob.
//! let claims = block_on(bank.validate(&retailer_token, now)).expect("claims");
//! assert!(claims
//!     .get(&example_dot_com, &bobs_id)
//!     .unwrap()
//!     .starts_with("I am Bob and retailer.com may debit my bank.com account"));
//! ```

use std::fmt;
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};

use async_trait::async_trait;
use base64::prelude::*;
use ed25519_dalek::{SignatureError, Signer, Verifier};
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

/// The category of error returned by a JWT operation
#[derive(Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// An authentication error
    Auth,
    Base64,
    Format,
    Json,
    NotFound,
    Time,
}

/// An error returned by a JWT operation
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    /// Construct a new [`Error`].
    pub fn new(kind: ErrorKind, message: String) -> Self {
        Self { kind, message }
    }

    /// Construct a new authentication [`Error`].
    pub fn auth<M: fmt::Display>(message: M) -> Self {
        Self::new(ErrorKind::Auth, message.to_string())
    }

    /// Construct a new JWT format [`Error`].
    pub fn format<M: fmt::Display>(cause: M) -> Self {
        Self::new(ErrorKind::Format, cause.to_string())
    }

    /// Construct a new JWT actor retrieval [`Error`].
    pub fn not_found<Info: fmt::Debug>(info: Info) -> Self {
        Self::new(ErrorKind::NotFound, format!("{info:?}"))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for Error {}

impl From<base64::DecodeError> for Error {
    fn from(cause: base64::DecodeError) -> Self {
        Self::new(ErrorKind::Base64, cause.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(cause: serde_json::Error) -> Self {
        Self::new(ErrorKind::Json, cause.to_string())
    }
}

impl From<SignatureError> for Error {
    fn from(cause: SignatureError) -> Self {
        Self::new(ErrorKind::Auth, cause.to_string())
    }
}

impl From<SystemTimeError> for Error {
    fn from(cause: SystemTimeError) -> Self {
        Self::new(ErrorKind::Time, cause.to_string())
    }
}

/// Trait which defines how to fetch an [`Actor`] given its host and ID
#[async_trait]
pub trait Resolve: Send + Sync {
    type HostId: Serialize + DeserializeOwned + PartialEq + fmt::Debug + Send + Sync;
    type ActorId: Serialize + DeserializeOwned + PartialEq + fmt::Debug + Send + Sync;
    type Claims: Serialize + DeserializeOwned + Send + Sync;

    /// Given a host and actor ID, return a corresponding [`Actor`].
    async fn resolve(
        &self,
        host: &Self::HostId,
        actor_id: &Self::ActorId,
    ) -> Result<Actor<Self::ActorId>, Error>;

    /// Validate and return the [`Claims`] of the given `encoded` token.
    async fn validate(
        &self,
        encoded: &str,
        now: SystemTime,
    ) -> Result<Claims<Self::HostId, Self::ActorId, Self::Claims>, Error> {
        let (message, signature) = token_signature(encoded)?;
        let token: Token<Self::HostId, Self::ActorId, Self::Claims> = decode_token(message)?;

        if token.is_expired(now) {
            return Err(Error::new(ErrorKind::Time, "token is expired".into()));
        }

        let actor = self.resolve(&token.iss, &token.actor_id).await?;

        if actor.id != token.actor_id {
            return Err(Error::auth(
                "attempted to use a bearer token for a different actor",
            ));
        }

        if let Err(cause) = actor.public_key().verify(message.as_bytes(), &signature) {
            return Err(Error::auth(format!("invalid bearer token: {cause}")));
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
    }
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
pub struct Actor<A> {
    id: A,
    public_key: VerifyingKey,
    private_key: Option<SigningKey>,
}

impl<A> Actor<A> {
    /// Return an `Actor` with a newly-generated keypair.
    pub fn new(id: A) -> Self {
        let private_key = SigningKey::generate(&mut OsRng);
        let public_key = private_key.verifying_key();

        Self {
            id,
            public_key,
            private_key: Some(private_key),
        }
    }

    /// Return an `Actor` with the given keypair, or an error if the keypair is invalid.
    pub fn with_keypair(id: A, public_key: &[u8], secret: &[u8]) -> Result<Self, Error> {
        let public_key = VerifyingKey::try_from(public_key)?;
        let private_key = SigningKey::try_from(secret)?;

        Ok(Self {
            id,
            public_key,
            private_key: Some(private_key),
        })
    }

    /// Return an `Actor` with the given public key, or an error if the key is invalid.
    pub fn with_public_key(id: A, public_key: &[u8]) -> Result<Self, Error> {
        let public_key = VerifyingKey::try_from(public_key)?;

        Ok(Self {
            id,
            public_key,
            private_key: None,
        })
    }

    /// Borrow the identifier of this actor.
    pub fn id(&self) -> &A {
        &self.id
    }

    /// Borrow the public key of this actor, which a client can use to verify a signature.
    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }

    /// Encode and sign the given `token`.
    pub fn sign_token<H, C>(&self, token: &Token<H, A, C>) -> Result<String, Error>
    where
        H: Serialize,
        A: Serialize,
        C: Serialize,
    {
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| Error::auth("cannot sign a token without a private key"))?;

        let header = BASE64_STANDARD.encode(serde_json::to_string(&TokenHeader::default())?);
        let claims = BASE64_STANDARD.encode(serde_json::to_string(&token)?);

        let signature = private_key.try_sign(format!("{header}.{claims}").as_bytes())?;
        let signature = BASE64_STANDARD.encode(signature.to_bytes());

        Ok(format!("{header}.{claims}.{signature}"))
    }
}

impl<A: Clone> Clone for Actor<A> {
    fn clone(&self) -> Self {
        Actor {
            id: self.id.clone(),
            public_key: self.public_key.clone(),
            private_key: None,
        }
    }
}

#[derive(Eq, PartialEq, Debug, Deserialize, Serialize)]
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

/// All the claims of a recursive [`Token`]
#[derive(Clone, Debug)]
pub struct Claims<H, A, C> {
    exp: u64,
    host: H,
    actor_id: A,
    claims: C,
    inherit: Option<Box<Claims<H, A, C>>>,
}

impl<H: PartialEq, A: PartialEq, C> Claims<H, A, C> {
    fn new(exp: u64, host: H, actor_id: A, claims: C) -> Self {
        Self {
            exp,
            host,
            actor_id,
            claims,
            inherit: None,
        }
    }

    fn consume(exp: u64, host: H, actor_id: A, claims: C, parent: Self) -> Self {
        Self {
            exp,
            host,
            actor_id,
            claims,
            inherit: Some(Box::new(parent)),
        }
    }

    pub fn expires(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.exp)
    }

    /// Get the most recent claim made by the specified [`Actor`].
    pub fn get(&self, host: &H, actor_id: &A) -> Option<&C> {
        if host == &self.host && actor_id == &self.actor_id {
            Some(&self.claims)
        } else if let Some(claims) = &self.inherit {
            claims.get(host, actor_id)
        } else {
            None
        }
    }
}

/// The JSON Web Token wire format
#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct Token<H, A, C> {
    iss: H,
    iat: u64,
    exp: u64,
    actor_id: A,
    custom: C,
    inherit: Option<String>,
}

impl<H, A, C> Token<H, A, C> {
    /// Create a new (unsigned) token.
    pub fn new(iss: H, iat: SystemTime, ttl: Duration, actor_id: A, claims: C) -> Self {
        let iat = iat.duration_since(UNIX_EPOCH).expect("duration");
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

    /// Create a new (unsigned) token which inherits from an existing (signed) token.
    pub fn consume(
        parent: String,
        iat: SystemTime,
        ttl: Duration,
        host: H,
        actor_id: A,
        claims: C,
    ) -> Result<Self, Error> {
        let iat = iat.duration_since(UNIX_EPOCH)?;
        let exp = iat + ttl;

        Ok(Self {
            iss: host,
            iat: iat.as_secs(),
            exp: exp.as_secs(),
            actor_id,
            custom: claims,
            inherit: Some(parent),
        })
    }

    /// Borrow the claimed issuer of this token.
    pub fn issuer(&self) -> &H {
        &self.iss
    }

    /// Borrow the actor to whom this token claims to belong.
    pub fn actor_id(&self) -> &A {
        &self.actor_id
    }

    /// Return `true` if this token is expired (or not yet issued) at the given moment.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        let iat = UNIX_EPOCH + Duration::from_secs(self.iat);
        let exp = UNIX_EPOCH + Duration::from_secs(self.exp);
        now < iat || now >= exp
    }
}

impl<H: fmt::Display, A: fmt::Display, C> fmt::Debug for Token<H, A, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "JWT token claiming to authenticate actor {} at host {}",
            self.actor_id, self.iss
        )
    }
}

fn token_signature(encoded: &str) -> Result<(&str, Signature), Error> {
    if encoded.ends_with('.') {
        return Err(Error::format("encoded token cannot end with ."));
    }

    let i = encoded
        .rfind('.')
        .ok_or_else(|| Error::format(format!("invalid token: {}", encoded)))?;

    let message = &encoded[..i];

    let signature = BASE64_STANDARD
        .decode(&encoded[(i + 1)..])
        .map_err(|e| Error::new(ErrorKind::Base64, e.to_string()))?;

    let signature = Signature::try_from(&signature[..])?;

    Ok((message, signature))
}

fn decode_token<H, A, C>(encoded: &str) -> Result<Token<H, A, C>, Error>
where
    H: DeserializeOwned,
    A: DeserializeOwned,
    C: DeserializeOwned,
{
    let i = encoded
        .find('.')
        .ok_or_else(|| Error::format(format!("invalid token: {}", encoded)))?;

    let header = BASE64_STANDARD.decode(&encoded[..i])?;
    let header: TokenHeader = serde_json::from_slice(&header)?;

    if header != TokenHeader::default() {
        return Err(Error::format(format!(
            "unsupported bearer token type: {header:?}"
        )));
    }

    let token = BASE64_STANDARD.decode(&encoded[(i + 1)..])?;
    let token = serde_json::from_slice(&token)?;

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE_LIMIT: usize = 8000; // max HTTP header size

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
        assert!(encoded.len() < SIZE_LIMIT);
    }
}
