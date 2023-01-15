"""A recursive Javascript Web :class:`Token`"""

from datetime import datetime, timedelta, timezone


class Token(object):
    """A recursive Javascript Web :class:`Token`"""

    HEADERS = {
        "alg": "ES256",
        "typ": "JWT",
    }

    @classmethod
    def issue(cls, issuer, actor_id, claims, ttl=30):
        """Issue a new :class:`Token` at the current system time with the given `claims`"""

        if isinstance(ttl, (int, float)):
            ttl = timedelta(seconds=ttl)

        issued_at = datetime.now(tz=timezone.utc)
        expires = issued_at + ttl
        return cls(issuer, actor_id, issued_at, expires, claims)

    @classmethod
    def consume(cls, parent, issuer, actor_id, claims, ttl=30):
        """Consume a signed `parent` :class:`Token` and issue a new child :class:`Token` containing it"""

        if isinstance(ttl, (int, float)):
            ttl = timedelta(seconds=ttl)

        issued_at = datetime.now(tz=timezone.utc)
        expires = issued_at + ttl
        return cls(issuer, actor_id, issued_at, expires, claims, parent)

    def __init__(self, iss, actor_id, iat, exp, custom=None, inherit=None):
        if isinstance(iat, (int, float)):
            iat = datetime.fromtimestamp(iat, timezone.utc)

        if isinstance(exp, (int, float)):
            exp = datetime.fromtimestamp(exp, timezone.utc)

        if exp < iat:
            raise ValueError(f"token cannot expire at {exp} when issued at {iat}")

        self.actor_id = actor_id
        self.iss = iss
        self.iat = iat
        self.exp = exp
        self.custom = custom
        self.inherit = inherit

    def __eq__(self, other):
        return (
            self.actor_id == other.actor_id,
            self.iss == other.iss,
            self.iat == other.iat,
            self.custom == other.custom,
            self.inherit == other.inherit)

    @property
    def claims(self):
        """The `claims` made by this :class:`Token`"""

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
