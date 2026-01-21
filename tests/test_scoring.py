from sift.scoring import compute_score, classify_score


def test_classification_levels():
    assert classify_score(90) == "CRITICAL"
    assert classify_score(70) == "HIGH"
    assert classify_score(45) == "MEDIUM"
    assert classify_score(10) == "LOW"


def test_score_boost_for_config_files():
    base = 60
    boosted = compute_score(base, in_config_file=True)

    assert boosted > base
    assert boosted <= 100
