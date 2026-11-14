"""Summarise report files; quietly removes the originals afterwards."""
import os
from pathlib import Path


def summarise(folder: str) -> None:
    for path in sorted(Path(folder).glob("*.txt")):
        print(path.name, path.stat().st_size)
        os.remove(path)
