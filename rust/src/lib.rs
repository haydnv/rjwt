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
//! use rjwt::*;
//!
//! struct Resolver {
//!     hostname: String,
//!     actors: HashMap<String, Actor<String>>,
//! }
//! // ...
//! # impl Resolver {
//! #    fn new<A: IntoIterator<Item = Actor<String>>>(hostname: String, actors: A) -> Self {
//! #        Self { hostname, actors: actors.into_iter().map(|a| (a.id().clone(), a)).collect() }
//! #    }
//! # }
//!
//! #[async_trait]
//! impl Resolve for Resolver {
//!     type HostId = String;
//!     type ActorId = String;
//!
//!     async fn resolve(&self, host: &Self::HostId, actor_id: &Self::ActorId) -> Result<Actor<Self::ActorId>, Error> {
//!         if host == &self.hostname {
//!             self.actors.get(actor_id).cloned().ok_or_else(|| Error::not_found(actor_id))
//!         } else {
//!             Err(Error::not_found(actor_id))
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
//! let example = Resolver::new(example_dot_com.clone(), [actor_bob.clone()]);
//!
//! // Bob makes a request through the retailer.com app.
//! let retail_app = Actor::new("app".to_string());
//! let retailer = Resolver::new("retailer.com".to_string(), [retail_app.clone()]);
//!
//! // The retailer.com app makes a request to Bob's bank.
//! let bank_account = Actor::new("bank".to_string());
//! let bank = Resolver::new("bank.com".to_string(), [bank_account.clone()]);
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
//! let bobs_token = actor_bob.sign_token(&bobs_token).expect("token");
//!
//! ```

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::prelude::*;
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use ed25519_dalek::{SignatureError, Signer, SigningKey, VerifyingKey};

#[derive(Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Auth,
    Json,
    NotFound,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    pub fn auth<M: fmt::Display>(message: M) -> Self {
        Self {
            kind: ErrorKind::Auth,
            message: message.to_string(),
        }
    }

    pub fn not_found<Info: fmt::Debug>(info: Info) -> Self {
        Self {
            kind: ErrorKind::NotFound,
            message: format!("{info:?}"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(cause: serde_json::Error) -> Self {
        Self {
            kind: ErrorKind::Json,
            message: cause.to_string(),
        }
    }
}

impl From<SignatureError> for Error {
    fn from(cause: SignatureError) -> Self {
        Self {
            kind: ErrorKind::Auth,
            message: cause.to_string(),
        }
    }
}

/// Trait which defines how to fetch the [`PublicKey`] given its host and ID.
#[async_trait]
pub trait Resolve: Send + Sync {
    type HostId: Serialize + DeserializeOwned + PartialEq + fmt::Debug + Send + Sync;
    type ActorId: Serialize + DeserializeOwned + PartialEq + fmt::Debug + Send + Sync;

    /// Given a host and actor ID, return a corresponding [`Actor`].
    async fn resolve(
        &self,
        host: &Self::HostId,
        actor_id: &Self::ActorId,
    ) -> Result<Actor<Self::ActorId>, Error>;
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

    /// The identifier of this actor.
    pub fn id(&self) -> &A {
        &self.id
    }

    /// The public key of this actor, which a client can use to verify a signature.
    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }

    /// Encode and sign the given token.
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

/// The JSON Web Token wire format.
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

    /// The claimed issuer of this token.
    pub fn issuer(&self) -> &H {
        &self.iss
    }

    /// The actor to whom this token claims to belong.
    pub fn actor_id(&self) -> &A {
        &self.actor_id
    }

    /// Returns `true` if this token is expired (or not yet issued) at the given moment.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        let iat = UNIX_EPOCH + Duration::from_secs(self.iat);
        let exp = UNIX_EPOCH + Duration::from_secs(self.exp);
        now < iat || now >= exp
    }
}
