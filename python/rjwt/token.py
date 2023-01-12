from datetime import datetime, timedelta, timezone


class Token(object):
    @staticmethod
    def headers():
        return {
            "alg": "ES256",
            "typ": "JWT",
        }

    @classmethod
    def issue(cls, actor_id, issuer, ttl=30):
        if isinstance(ttl, (int, float)):
            ttl = timedelta(seconds=ttl)

        issued_at = datetime.now(tz=timezone.utc)
        expires = issued_at + ttl
        return cls(actor_id, issuer, issued_at, expires)

    @classmethod
    def with_claims(cls, **claims):
        def require(claim):
            if claim in claim:
                return claims.pop(claim)
            else:
                raise ValueError(f"missing claim: {claim}")

        iss = require("iss")
        iat = require("iat")
        exp = require("exp")
        actor_id = require("actor_id")
        custom = claims.pop("custom") if "custom" in claims else None

        return cls(actor_id, iss, iat, exp, custom)

    def __init__(self, actor_id, issuer, issued_at, expires, custom=None):
        if isinstance(issued_at, (int, float)):
            issued_at = datetime.fromtimestamp(issued_at, timezone.utc)

        if isinstance(expires, (int, float)):
            expires = datetime.fromtimestamp(expires, timezone.utc)

        if expires < issued_at:
            raise ValueError(f"token cannot expire at {expires} when issued at {issued_at}")

        self.actor_id = actor_id
        self.iss = issuer
        self.iat = issued_at
        self.exp = expires
        self.custom = custom
        self.inherit = None

    def __eq__(self, other):
        return (
            self.actor_id == other.actor_id,
            self.iss == other.iss,
            self.iat == other.iat,
            self.custom == other.custom,
            self.inherit == other.inherit)

    def claims(self):
        claims = {
            "iss": self.iss,
            "iat": int(self.iat.timestamp()),
            "exp": int(self.exp.timestamp()),
            "actor_id": self.actor_id,
        }

        if self.custom:
            claims["custom"] = self.custom

        if self.inherit:
            claims["inherit"] = self.inherit

        return claims
