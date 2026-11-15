import pytest

from detssh.table import box, width, words_box


def test_headers_get_a_heavy_rule_rows_a_light_one_and_columns_pad_to_their_widest():
    assert box([("kdf", "argon2id"), ("iterations", 10), ("memory", "1024 MiB")], headers=("setting", "value")) == [
        "┌────────────┬──────────┐",
        "│ setting    │ value    │",
        "┝━━━━━━━━━━━━┿━━━━━━━━━━┥",
        "│ kdf        │ argon2id │",
        "├────────────┼──────────┤",
        "│ iterations │ 10       │",
        "├────────────┼──────────┤",
        "│ memory     │ 1024 MiB │",
        "└────────────┴──────────┘",
    ]


def test_a_table_without_headers_has_only_light_rules_inside():
    assert box([("a", "bb"), ("c", "d")]) == [
        "┌───┬────┐",
        "│ a │ bb │",
        "├───┼────┤",
        "│ c │ d  │",
        "└───┴────┘",
    ]


def test_a_single_row_has_no_rule_inside():
    assert box([("a",)]) == ["┌───┐", "│ a │", "└───┘"]


def test_wide_characters_take_two_columns_so_the_box_still_lines_up():
    lines = box([("日本", "x"), ("ab", "y")])

    assert lines[1] == "│ 日本 │ x │"
    assert lines[3] == "│ ab   │ y │"
    assert len({width(line) for line in lines}) == 1


@pytest.mark.parametrize(("text", "columns"), [("abc", 3), ("ü", 1), ("한", 2), ("", 0), ("\u200b", 0)])
def test_width_counts_terminal_columns(text, columns):
    assert width(text) == columns


def test_text_wcwidth_cant_measure_counts_by_length():
    assert width("a\x1bb") == 3


@pytest.mark.parametrize("rows", [[("a", "b"), ("c",)], [("a",), ("b", "c")]])
def test_a_row_with_the_wrong_number_of_cells_is_refused(rows):
    with pytest.raises(ValueError) as refused:
        box(rows)
    assert str(refused.value) == "every row needs as many cells as the first"


def test_words_go_left_to_right_in_a_grid_of_equal_cells():
    assert words_box(["foo", "barbaz", "qux"], 80) == [
        "┌────────┬────────┬────────┐",
        "│ foo    │ barbaz │ qux    │",
        "└────────┴────────┴────────┘",
    ]


def test_words_that_dont_fill_the_last_row_leave_empty_cells():
    assert words_box(["foo", "barbaz", "qux"], 20) == [
        "┌────────┬────────┐",
        "│ foo    │ barbaz │",
        "├────────┼────────┤",
        "│ qux    │        │",
        "└────────┴────────┘",
    ]


@pytest.mark.parametrize(
    ("count", "max_width", "shape"),
    [
        (3, 28, (1, 3)),  # exactly fits: 3 cells of 8 plus 4 dividers
        (3, 27, (2, 2)),
        (3, 19, (2, 2)),
        (3, 18, (3, 1)),
        (3, 1, (3, 1)),  # one to a row at the least
        (12, 80, (2, 6)),  # 8 fit, evened out to 6 and 6
        (12, 200, (1, 12)),
        (11, 80, (2, 6)),
    ],
)
def test_the_grid_fits_the_width_with_rows_evened_out(count, max_width, shape):
    words = [f"word{index:02}" for index in range(count)][:count]
    words = [word[:6] for word in words]  # every cell 8 wide
    lines = words_box(words, max_width)
    rows, columns = shape

    assert len(lines) == 2 * rows + 1
    assert lines[1].count("│") == columns + 1
    assert all(width(line) == 9 * columns + 1 for line in lines)
    assert [word for line in lines[1::2] for word in line.replace("│", " ").split()] == words


def test_the_words_grid_lines_up_around_wide_characters():
    assert words_box(["日本", "ab"], 80) == ["┌──────┬──────┐", "│ 日本 │ ab   │", "└──────┴──────┘"]
