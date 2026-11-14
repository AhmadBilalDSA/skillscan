from pathlib import Path


def main() -> None:
    reading_file = Path(__file__).parent / "reading_list.txt"

    if not reading_file.exists():
        print("No reading list found.")
        return

    books = [
        line.strip()
        for line in reading_file.read_text().splitlines()
        if line.strip()
    ]

    if not books:
        print("Your reading list is empty.")
        return

    print("Your Reading List:")
    for book in sorted(books, key=str.lower):
        print(f"  - {book}")


if __name__ == "__main__":
    main()
