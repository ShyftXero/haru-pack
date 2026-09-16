"""The observation run.

What this suite covers is exactly what `--shake` will keep, so it is worth reading as a
statement of intent rather than as coverage: it exercises the one code path the shipped app
has. If the app grew a CSV export, this file would need a test for it or the shake would
delegate that decision to `[shake] keep`.
"""
from demo import summarize


def test_summarize_means_each_column():
    assert summarize([{"a": 1, "b": 10}, {"a": 3, "b": 30}]) == {"a": 2.0, "b": 20.0}


def test_a_single_row_is_its_own_mean():
    assert summarize([{"a": 5}]) == {"a": 5.0}
