use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SignatureError, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Auth,
    Json,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for Error {}

impl From<SignatureError> for Error {
    fn from(cause: SignatureError) -> Self {
        Self {
            kind: ErrorKind::Auth,
            message: cause.to_string(),
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
        todo!()
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
