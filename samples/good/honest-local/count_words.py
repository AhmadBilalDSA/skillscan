"""Count words in a local text file and print the most common ones."""
import re
from collections import Counter
from pathlib import Path


def main() -> None:
    text = Path("text.txt").read_text(encoding="utf-8")
    words = re.findall(r"[a-z']+", text.lower())
    for word, count in Counter(words).most_common(10):
        print(f"{word}: {count}")


if __name__ == "__main__":
    main()
