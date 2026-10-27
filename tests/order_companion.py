"""A second module for the order tests in test_malformed_input.py to interleave with.

Its name does not match pytest's test_*.py pattern, so a normal run does not collect it; those tests name it on a child
pytest's command line. It lives in the repository so that both files the child collects are inside the rootdir: for a
file outside it, pytest lists every directory above that file (up to the drive), and a temporary folder that another
process removes during that listing stops the child's collection.
"""


def test_other_0():
    pass


def test_other_1():
    pass


def test_other_2():
    pass


def test_other_3():
    pass


def test_other_4():
    pass


def test_other_5():
    pass


def test_other_6():
    pass


def test_other_7():
    pass


def test_other_8():
    pass


def test_other_9():
    pass


def test_other_10():
    pass


def test_other_11():
    pass


def test_other_12():
    pass


def test_other_13():
    pass


def test_other_14():
    pass


def test_other_15():
    pass


def test_other_16():
    pass


def test_other_17():
    pass


def test_other_18():
    pass


def test_other_19():
    pass
