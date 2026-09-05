# Digest test fixtures

`command-corpus.json` is the oracle for shell-command classification. It mixes
commands from recorded runs, review regressions, and focused contract shapes.
Add a case with explicit empty `want_*` lists, a source, and a one-line note
only when the deciding rule is not obvious. Optional `output`, `retry`, and
`failure` fields cover facts that command text alone cannot exercise.

Derive expectations from the classifier contract and standing rulings, never
by recording current behavior. Mark a known implementation difference with
`disagrees_with_impl` and a one-line `disagreement`; the test skips it visibly.

The JSONL files are small, hand-authored synthetic agent streams. Keep those
fixtures invented and prefer focused inline fixtures for new parser cases.
