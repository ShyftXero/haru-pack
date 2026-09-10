"""A deliberately narrow app on top of a deliberately wide dependency.

`--shake` is only interesting when the gap between "what the resolver installed" and "what
the program runs" is large. This module is that gap in miniature: it imports pandas and
uses one reduction out of it, and never touches HDF5, Excel, SQL, plotting, clipboard,
Parquet, or any of the optional backends whose stubs and native shims ship in the wheel.
"""
from __future__ import annotations

import pandas as pd


def summarize(rows):
    """Column means for a list of records. The whole feature surface."""
    return pd.DataFrame(rows).mean().to_dict()


def main():
    print(summarize([{"a": 1, "b": 10}, {"a": 3, "b": 30}]))


if __name__ == "__main__":
    main()
