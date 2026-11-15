"""Boxed output for --pretty: `box([("kdf", "argon2id"), ...], headers=("setting", "value"))` for a
table, `words_box(words, 80)` for a seed's words in a grid."""

from wcwidth import wcswidth


def width(text):
    """How many terminal columns `text` takes: 2 for each wide character (日, 한), so a column of
    them still lines up. Text wcwidth can't measure (control characters) counts by length."""
    columns = wcswidth(text)
    return len(text) if columns < 0 else columns


def _padded(text, columns):
    return f"{text}{' ' * (columns - width(text))}"


def box(rows, headers=None):
    """`rows` drawn in a box, as a list of lines: a heavy rule under `headers`, a light one between
    rows. Every row has as many cells as the first; cells are padded to their column's widest."""
    table = [tuple(str(cell) for cell in row) for row in ([headers] if headers else []) + list(rows)]
    if len({len(row) for row in table}) > 1:
        raise ValueError("every row needs as many cells as the first")
    widths = [max(width(row[column]) for row in table) for column in range(len(table[0]))]

    def rule(left, line, middle, right):
        return left + middle.join(line * (column + 2) for column in widths) + right

    def line(row):
        return "│" + "│".join(f" {_padded(cell, column)} " for cell, column in zip(row, widths, strict=True)) + "│"

    lines = [rule("┌", "─", "┬", "┐")]
    for index, row in enumerate(table):
        if index == 1 and headers:
            lines.append(rule("┝", "━", "┿", "┥"))  # heavy across, joining the light dividers
        elif index:
            lines.append(rule("├", "─", "┼", "┤"))
        lines.append(line(row))
    lines.append(rule("└", "─", "┴", "┘"))
    return lines


def words_box(words, max_width):
    """The words left to right in a grid of equal cells, as many to a row as fit in `max_width`
    columns (one at the least). Rows are evened out - 12 words that fit 7 to a row go 6 and 6 -
    and whatever the last row doesn't fill is left as empty cells, so the grid is always a full
    rectangle."""
    cell = max(width(word) for word in words) + 2
    fit = max(1, (max_width - 1) // (cell + 1))  # each cell plus the divider before it, then the last one
    rows = -(-len(words) // fit)
    columns = -(-len(words) // rows)

    def rule(left, middle, right):
        return left + middle.join("─" * cell for _ in range(columns)) + right

    lines = [rule("┌", "┬", "┐")]
    for row in range(rows):
        if row:
            lines.append(rule("├", "┼", "┤"))
        texts = words[row * columns : (row + 1) * columns]
        texts += [""] * (columns - len(texts))
        lines.append("│" + "│".join(f" {_padded(text, cell - 2)} " for text in texts) + "│")
    lines.append(rule("└", "┴", "┘"))
    return lines
