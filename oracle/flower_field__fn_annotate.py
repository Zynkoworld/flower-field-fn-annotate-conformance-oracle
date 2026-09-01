"""flower-field-fn-annotate-conformance-oracle -- deterministic CONFORMANCE oracle for `flower-field` (python).

WHAT THIS DECIDES: given a candidate callable and one canonical input, it decides whether the candidate
agrees with the proven reference. It is a *conformance* decider over a fixed, published corpus -- it does
not decide correctness in general, and it says nothing about inputs outside the corpus.

SCOPE (declared, so the boundary is visible rather than discovered): the corpus is the canonical Exercism
test data for this task, 8 input/output pairs, listed in `probes/probes.jsonl`. Inputs outside that
set are simply not covered; `decide` answers only about the input it is given.

PROVENANCE: the reference body comes from the Exercism reference solution for `flower-field` (MIT, Exercism);
the type annotations were added by harvest, the body is unchanged (checked at AST level). The capability
was PROVEN by the exercism testsuite (pin=1af949f11348a1a9) and re-executed by harvest in a sealed sandbox
(unshare -rn) -- verify-not-relay, not a copied ledger label.
"""

TASK = "flower-field"
CWE = "flower-field"          # a publish-motor egyseges mezonevet var; itt a feladat azonositoja


def decide(fn, value, expect):
    """PASS iff fn(value) == expect. Determinista, nincs halozat, nincs allapot."""
    try:
        return "PASS" if fn(value) == expect else "FAIL"
    except Exception:                                      # noqa: BLE001
        return "FAIL"


def verify_board(garden):
    row_len = len(garden[0])
    if not all((len(row) == row_len for row in garden)):
        raise ValueError('The board is invalid with current input.')
    character_set = set()
    for row in garden:
        character_set.update(row)
    if character_set - set(' *'):
        raise ValueError('The board is invalid with current input.')

def annotate(garden: list) -> list:
    if not garden:
        return []
    verify_board(garden)
    row_len = len(garden[0])
    col_len = len(garden)
    board = [list(row) for row in garden]
    for index1 in range(col_len):
        for index2 in range(row_len):
            if board[index1][index2] != ' ':
                continue
            low = max(index2 - 1, 0)
            high = min(index2 + 2, row_len + 2)
            counts = garden[index1][low:high].count('*')
            if index1 > 0:
                counts += garden[index1 - 1][low:high].count('*')
            if index1 < col_len - 1:
                counts += garden[index1 + 1][low:high].count('*')
            if counts == 0:
                continue
            board[index1][index2] = str(counts)
    return [''.join(row) for row in board]

REFERENCE = annotate
