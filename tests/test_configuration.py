import pytest

from fortressflag._configuration import (
    Configuration,
    MalformedKeyError,
    key_prefix,
    parse_key,
    resolve_configuration,
)


def test_a_secret_containing_underscores_parses_the_split_trap() -> None:
    # The secret is base64url; its alphabet includes "_". maxsplit=2 keeps the remainder.
    assert parse_key("ffs_dev_abc_def_ghi") == "dev"


def test_well_formed_keys_parse() -> None:
    assert parse_key("ffs_prod_k12345") == "prod"
    assert parse_key("ffs_my-env_secret") == "my-env"


@pytest.mark.parametrize(
    "raw",
    ["", "ffs", "ffs_dev", "ffs_dev_", "ffc_dev_k", "ffs_D_k", "ffs_a_k", "ffs_-ab_k", "ffs_ab-_k"],
)
def test_malformed_keys_are_refused(raw: str) -> None:
    assert parse_key(raw) is None


def test_key_prefix_is_the_only_loggable_form() -> None:
    assert key_prefix("ffs_dev_abcdefghij") == "ffs_dev_abcdef"
    assert key_prefix("nonsense") == ""
    assert key_prefix("ffs_dev_abc") == ""


def test_the_one_raise_path_never_echoes_the_key() -> None:
    with pytest.raises(MalformedKeyError) as exc_info:
        resolve_configuration(Configuration(key="hunter2-the-actual-secret"))
    assert "hunter2" not in str(exc_info.value)


def test_defaults_and_the_poll_floor() -> None:
    resolved = resolve_configuration(Configuration(key="ffs_dev_k12345", poll_interval_s=5.0))
    assert resolved.base_url == "https://edge.fortressflag.com"
    assert resolved.poll_interval_s == 30.0  # floored at the contract's 30s
    assert resolved.http_timeout_s == 10.0
    assert resolved.environment == "dev"


def test_a_trailing_slash_on_base_url_is_trimmed() -> None:
    resolved = resolve_configuration(Configuration(key="ffs_dev_k12345", base_url="http://x/"))
    assert resolved.base_url == "http://x"


def test_the_production_trust_store_is_one_raw_32_byte_key_and_the_default() -> None:
    from fortressflag._configuration import FORTRESSFLAG_PRODUCTION, SIGNATURE_DISABLED

    assert list(FORTRESSFLAG_PRODUCTION) == ["prod-2026-09-k1"]
    assert len(FORTRESSFLAG_PRODUCTION["prod-2026-09-k1"]) == 32
    default = Configuration(key="ffs_dev_k12345").signature
    assert default.required and dict(default.trusted_keys) == dict(FORTRESSFLAG_PRODUCTION)
    assert not SIGNATURE_DISABLED.required
