"""
tests — stdlib unittest, no third-party test runner required.

Run everything:
    cd Entreprise && python -m unittest discover -s tests -v

Run one module:
    cd Entreprise && python -m unittest tests.test_schema_validate -v

pytest is not installed in the `shiva` environment, and installing it would
need approval that is not worth spending on a test runner. Every test here is a
`unittest.TestCase`, which pytest also collects unchanged, so nothing is lost if
it is added later.
"""
