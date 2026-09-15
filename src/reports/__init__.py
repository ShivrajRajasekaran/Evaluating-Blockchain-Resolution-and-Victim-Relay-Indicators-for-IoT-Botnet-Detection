"""
reports — turn results into tables, figures and documentation.

    tables.py       write results/tables/*.csv with a provenance header row
    figures.py      write results/figures/*.png
    generate_docs.py  render docs/ sections that are DERIVED from the schema
                      (the feature catalogue, the IoT-23 availability table)

Every artefact carries its track's disclaimer string from src.config
(provenance_note / real_data_note). That is not decoration: a CSV of metrics
with no provenance column is the exact artefact that ends up pasted into a
paper as a real-world performance claim.

The availability tables are GENERATED from src.schema.columns rather than typed
into the documentation by hand, so the write-up cannot claim a feature is
computable from IoT-23 after the code has been changed to say otherwise.
"""
