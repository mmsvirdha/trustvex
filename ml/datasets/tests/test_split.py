# Tests for the leakage-safe grouped split.

import random
from ml.datasets.prepare import stratified_group_split


def make_rows():
    """Synthetic rows: 10 domains per class, 2 URLs each = 40 rows."""
    rng = random.Random(0)
    rows = []
    for label in (0, 1):
        for i in range(10):
            g = f"example{label}-{i}.com"
            for _ in range(2):
                rows.append({
                    "group": g,
                    "label": label,
                    "url_length": rng.randint(10, 100),
                })
    return rows


def test_no_group_overlap_between_splits():
    rows = make_rows()
    train, val, test, stats = stratified_group_split(rows, 0.7, 0.15, 42)
    train_g = {r["group"] for r in train}
    val_g = {r["group"] for r in val}
    test_g = {r["group"] for r in test}
    assert not (train_g & val_g)
    assert not (train_g & test_g)
    assert not (val_g & test_g)


def test_all_rows_accounted_for():
    rows = make_rows()
    train, val, test, _ = stratified_group_split(rows, 0.7, 0.15, 42)
    assert len(train) + len(val) + len(test) == len(rows)


def test_both_classes_in_each_split():
    rows = make_rows()
    train, val, test, stats = stratified_group_split(rows, 0.7, 0.15, 42)
    for split in (train, val, test):
        labels = {r["label"] for r in split}
        assert labels == {0, 1}, f"expected both classes, got {labels}"