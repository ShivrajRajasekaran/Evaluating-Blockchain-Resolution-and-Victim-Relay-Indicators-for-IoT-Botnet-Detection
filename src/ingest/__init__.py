"""
ingest — the only two places observations are created.

    mock_generator.py   Track B. Locally sampled numeric feature values for the
                        blockchain-resolution / victim-relay classes plus benign
                        controls. Sends nothing, resolves nothing.
    iot23.py            Track A. Aggregates a locally held IoT-23 Zeek
                        conn.log.labeled into device-5-minute windows.

Both emit frames through src.schema.build_observations, so provenance,
label mapping and quality flags cannot drift between them.

Every ingest module writes to data/processed/ and treats data/raw/ as
read-only. Neither downloads anything: the IoT-23 adapter takes a local file
path and fails with an explanatory message if it is absent.
"""
