# tests/test_closure.py
"""Phase 1: closure primitives — matching, extract, store."""
from kairos.core.extract import ExtractConfig, ExtractMode, extract
from kairos.core.matching import Strategy, matches, normalize, tokenize
from kairos.core.store import TokenStore
from kairos.core.tokens import Level

IBAN = "DE89370400440532013000"
FILENAME = "bill-december-2023.txt"


# --- matching ---------------------------------------------------------------
def test_normalize_and_tokenize() -> None:
    assert normalize("  Hello   World ") == "hello world"
    assert tokenize("Pay 98.70 EUR") == {"pay", "98", "70", "eur"}


def test_matches_exact_normalized() -> None:
    assert matches(IBAN, IBAN, Strategy.EXACT)
    assert not matches(IBAN, IBAN.lower(), Strategy.EXACT)
    assert matches(IBAN, IBAN.lower(), Strategy.NORMALIZED)


def test_matches_fuzzy_threshold() -> None:
    assert matches("DE8937", "DE8938", Strategy.FUZZY, fuzzy_threshold=2)
    assert not matches("DE8937", "XX0000", Strategy.FUZZY, fuzzy_threshold=2)


# --- extract ----------------------------------------------------------------
def test_extract_all_tokens_filters() -> None:
    out = extract("Pay the invoice to the landlord", ExtractConfig())
    assert "the" not in out          # stopword
    assert "to" not in out           # len < 3
    assert "invoice" in out and "landlord" in out


def test_extract_specific_fields_preserves_case() -> None:
    cfg = ExtractConfig(mode=ExtractMode.SPECIFIC_FIELDS, fields=["recipient", "amount"])
    out = extract({"recipient": IBAN, "amount": 98.70, "memo": "rent"}, cfg)
    assert out == [IBAN, "98.7"]     # case preserved; memo ignored


def test_extract_regex() -> None:
    cfg = ExtractConfig(mode=ExtractMode.REGEX, pattern=r"DE\d{20}")
    assert extract(f"send to {IBAN} now", cfg) == [IBAN]


# --- store: trust axis ------------------------------------------------------
def test_seed_then_derivable() -> None:
    s = TokenStore()
    assert not s.derivable("invoice", Strategy.NORMALIZED)   # empty closure
    s.seed("Pay the invoice in bill-december-2023.txt")
    assert s.derivable("invoice", Strategy.NORMALIZED)
    assert s.derivable("december", Strategy.NORMALIZED)


def test_admit_specific_fields_makes_iban_derivable_exact() -> None:
    s = TokenStore()
    cfg = ExtractConfig(mode=ExtractMode.SPECIFIC_FIELDS, fields=["recipient"])
    s.admit({"recipient": IBAN}, "read_file", trusted=True, level=None,
            branch_origin=None, extract_cfg=cfg)
    assert s.derivable(IBAN, Strategy.EXACT)


def test_all_tokens_iban_needs_normalized_not_exact() -> None:
    s = TokenStore()
    s.admit(f"payee {IBAN}", "read_file", trusted=True, level=None,
            branch_origin=None, extract_cfg=ExtractConfig())
    assert not s.derivable(IBAN, Strategy.EXACT)        # stored lowercased
    assert s.derivable(IBAN, Strategy.NORMALIZED)


def test_token_split_is_closure_wide() -> None:
    s = TokenStore()
    cfg = ExtractConfig(mode=ExtractMode.SPECIFIC_FIELDS, fields=["a", "b"])
    s.admit({"a": "acme corp", "b": "berlin"}, "read_file", trusted=True, level=None,
            branch_origin=None, extract_cfg=cfg)
    # "acme berlin" spans two separate closure tokens — per-token would fail,
    # closure-wide passes.
    assert s.derivable("acme berlin", Strategy.TOKEN_SPLIT)
    assert not s.derivable("acme tokyo", Strategy.TOKEN_SPLIT)


# --- store: sensitivity axis ------------------------------------------------
def test_sensitivity_of() -> None:
    s = TokenStore()
    cfg = ExtractConfig(mode=ExtractMode.SPECIFIC_FIELDS, fields=["balance"])
    s.admit({"balance": "4823"}, "get_balance", trusted=True, level=Level.HIGH,
            branch_origin=None, extract_cfg=cfg)
    assert s.sensitivity_of("4823", strategy=Strategy.NORMALIZED) is Level.HIGH
    assert s.sensitivity_of("0000") is None


# --- store: branch isolation + reconciliation (§4.3, §4.9) ------------------
def test_branch_isolation_and_commit_abort() -> None:
    s = TokenStore()
    cfg = ExtractConfig(mode=ExtractMode.SPECIFIC_FIELDS, fields=["x"])
    s.admit({"x": IBAN}, "read_file", trusted=True, level=None,
            branch_origin="b1", extract_cfg=cfg)
    assert not s.derivable(IBAN, Strategy.EXACT)             # not on committed
    assert s.derivable(IBAN, Strategy.EXACT, branch="b1")    # visible in branch

    s.abort_branch("b1")
    assert not s.derivable(IBAN, Strategy.EXACT, branch="b1")  # dropped

    s.admit({"x": IBAN}, "read_file", trusted=True, level=None,
            branch_origin="b2", extract_cfg=cfg)
    s.commit_branch("b2")
    assert s.derivable(IBAN, Strategy.EXACT)                 # promoted to committed

def test_seed_preserves_full_filename() -> None:
    s = TokenStore()
    s.seed(f"Pay the invoice in {FILENAME}")
    # coarse subwords still present (all_tokens behaviour unchanged)
    assert s.derivable("invoice", Strategy.NORMALIZED)
    # full filename now matchable exactly — this is the precision we wanted
    assert s.derivable(FILENAME, Strategy.EXACT)
    assert s.derivable(FILENAME, Strategy.NORMALIZED)

# test preserving whole identifiers prevents overauthorization of subwords (e.g. "2023.txt" is not a filename token, so not derivable) — this is a key motivation for preservation patterns.
def test_seed_preserves_iban_and_url_whole() -> None:
    s = TokenStore()
    s.seed(f"send to {IBAN} and confirm at https://bank.example/confirm?id=7")
    assert s.derivable(IBAN, Strategy.EXACT)
    assert s.derivable("https://bank.example/confirm?id=7", Strategy.EXACT)


def test_token_split_would_overauthorize_filenames() -> None:
    # documents WHY preservation matters: token_split authorizes the wrong file
    s = TokenStore()
    s.seed(f"Pay the invoice in {FILENAME}")
    assert s.derivable("2023.txt", Strategy.TOKEN_SPLIT)       # loose: wrong file passes
    assert not s.derivable("2023.txt", Strategy.EXACT)         # exact on full name: rejected


def test_filename_regex_ignores_decimal_amounts() -> None:
    s = TokenStore()
    s.seed("transfer 98.70 to landlord")
    assert not s.derivable("98.70", Strategy.EXACT)  # "98.70" is not a filename token

def test_seed_url_also_authorizes_origin_for_other_paths() -> None:
    s = TokenStore()
    s.seed("fetch my data from https://api.bank.example/v2/data")
    # the exact URL the user named:
    assert s.derivable("https://api.bank.example/v2/data", Strategy.NORMALIZED)
    # a DIFFERENT path under the same host -> origin token authorizes it:
    assert s.derivable("https://api.bank.example", Strategy.NORMALIZED)
    # but NOT a different host:
    assert not s.derivable("https://evil.example", Strategy.NORMALIZED)