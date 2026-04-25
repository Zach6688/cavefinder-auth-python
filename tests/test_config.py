from cavefinder_auth import AuthConfig


def test_is_public_path_matches_exact_and_subpath():
    cfg = AuthConfig(
        issuer="x",
        jwks_url="y",
        login_url="z",
        public_paths=("/api/healthz", "/static", "/view"),
    )
    assert cfg.is_public_path("/api/healthz")
    assert cfg.is_public_path("/static/app.css")
    assert cfg.is_public_path("/view/abc-123")
    assert not cfg.is_public_path("/api/me")
    assert not cfg.is_public_path("/viewers")   # "/view" must NOT match "/viewers"
    assert not cfg.is_public_path("/staticfoo")


def test_is_public_path_handles_trailing_slash():
    cfg = AuthConfig(issuer="x", jwks_url="y", login_url="z", public_paths=("/api/",))
    assert cfg.is_public_path("/api/anything")
    assert cfg.is_public_path("/api/")


def test_defaults():
    cfg = AuthConfig(issuer="x", jwks_url="y", login_url="z")
    assert cfg.cookie_name == "__Secure-cf_at"
    assert cfg.jwks_cache_ttl == 3600
    assert cfg.jwks_stale_ttl == 86400
    assert cfg.jwt_leeway == 30
    assert cfg.public_paths == ()
