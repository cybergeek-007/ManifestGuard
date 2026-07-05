"""ManifestGuard — Labeled evaluation dataset.

Two labeled sets used to measure detector quality:

  MALICIOUS: extension IDs drawn from public malware research and the
    project's own malicious corpus (tests/test_50_malicious_fast.py),
    including well-documented real incidents:
      - dknlfmjaanfblgfdfebhijalfmhmjjjo  "The Great Suspender" (supply-chain hijack, 2021)
      - biihmcacfjcankndbnogbbhkgimplicl  Fake ChatGPT extension (session stealer)

  SAFE: extension IDs of widely trusted, high-install extensions that a
    correct detector must NOT flag as malicious. Used to measure the
    false-positive rate — the metric that separates a usable tool from a
    noisy one.

Labels are the ground truth. The harness compares each verdict from the
live pipeline against these labels.

NOTE: Chrome Web Store IDs change availability over time. The harness
skips any ID that cannot be resolved/downloaded and reports coverage so
metrics are always computed over the successfully analyzed subset.
"""
from __future__ import annotations

# ── Known-malicious / high-risk (label = "malicious") ───────
MALICIOUS_IDS: list[str] = [
    "dknlfmjaanfblgfdfebhijalfmhmjjjo",  # The Great Suspender (hijacked)
    "biihmcacfjcankndbnogbbhkgimplicl",  # Fake ChatGPT
    "aaakfiobbojanlacpbeejjimehmpoffh",
    "aacfibelemnkkbkelbhdbfhokeemfaho",
    "aaddmojoibcjdlghmeeeenlgenaogcif",
    "aadmpgppfacognoeobmheghfiibdplcf",
    "aadnmeanpbokjjahcnikajejglihibpd",
    "aaeohfpkhojgdhocdfpkdaffbehjbmmd",
    "aafibkjcplagpjkhkeamkpaellnglepe",
    "aahjpoblnboigndgjiijcnbahniepnbo",
    "aaiolimgbncdaldgbbjkidiijidchhjo",
    "aajdkangkldmljmoaoehmbnchdjkgojk",
    "aapdalkmclfaahehnmicbglkohkldhne",
    "abbngaojehjekanfdipifimgmppiojpl",
    "abclkepfnkmfkhohoogobbekdcdghaoi",
    "abekedpmkgndeflcidpkkddapnjnocjp",
    "abgbjkemnkollcpimnfnmoakjedaenfd",
    "abgfholnofpihncfdmombecmohpkojdb",
    "abghmipjfclfpgmmelbgolfgmhnigbma",
    "abgpfcaflplbnjkpeoimjchehdhakped",
    "abigbbblmfhbgbjjdolageghdkdibeap",
    "abjbfhcehjndcpbiiagdnlfolkbfblpb",
    "abkebhncjihnoblbkcmhogfdpdmdklhg",
    "abkolnpebgghiglkkdjcgjgbpnddmfmp",
    "abpcbpoghgmfjkkdoeknbldhkklpcmfn",
]

# ── Widely trusted, high-install (label = "safe") ───────────
# Correct detector must NOT flag these as malicious/suspicious.
SAFE_IDS: list[str] = [
    "cjpalhdlnbpafiamejdnhcphjbkeiagm",  # uBlock Origin
    "gcbommkclmclpchllfjekcdonpmejbdp",  # HTTPS Everywhere
    "cfhdojbkjhnklbpkdaibdccddilifddb",  # Adblock Plus
    "aapbdbdomjkkjkaonfhkkikfgjllcleb",  # Google Translate
    "gighmmpiobklfepjocnamgkkbiglidom",  # AdBlock
    "nkbihfbeogaeaoehlefnkodbefgpgknn",  # MetaMask
    "bmnlcjabgnpnenekpadlanbbkooimhnj",  # Honey
    "fmkadmapgofadopljbjfkapdkoienihi",  # React DevTools
    "lmhkpmbekcpmknklioeibfkpmmfibljd",  # Redux DevTools
    "eimadpbcbfnmbkopoojfekhnkhdbieeh",  # Dark Reader
    "kbfnbcaeplbcioakkpcpgfkobkghlhen",  # Grammarly
    "hdokiejnpimakedhajhdlcegeplioahd",  # LastPass
    "chphlpgkkbolifaimnlloiipkdnihall",  # OneTab
    "oldceeleldhonbafppcapldpdifcinji",  # Grammarly (langauge)
    "mooikfkahbdckldjjndioackbalphokd",  # Selenium IDE
    "gppongmhjkpfnbhagpmjfkannfbllamg",  # Wappalyzer
    "iaiomicjabeggjcfkbimgmglanimpnae",  # Tab Manager
    "dbepggeogbaibhgnhhndojpepiihcmeb",  # Vimium
    "cofdbpoegempjloogbagkncekinflcnj",  # DuckDuckGo Privacy
    "pioclpoplcdbaefihamjohnefbikjilc",  # Evernote Web Clipper
]


def labeled_samples() -> list[tuple[str, str]]:
    """Return (extension_id, label) pairs for the full dataset."""
    samples = [(eid, "malicious") for eid in MALICIOUS_IDS]
    samples += [(eid, "safe") for eid in SAFE_IDS]
    return samples
