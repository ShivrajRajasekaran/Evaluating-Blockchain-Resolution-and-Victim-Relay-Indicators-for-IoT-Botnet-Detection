"""
services — offline scoring.

    score.py    load a trained detector, score a local CSV, write a local CSV

CONTAINMENT (binding — docs/ethics-and-containment.md)
    This module opens no socket, binds no port, starts no server, resolves no
    name, and forwards no packet. It is a batch function over files. There is
    deliberately no HTTP layer: an "IoT botnet detection service" that listens
    on a port is one configuration mistake away from being reachable, and this
    project has no reason to accept that risk to demonstrate a classifier.

ABSTENTION, NOT AN "UNKNOWN" CLASS
    When the schema fails to validate, required features are missing, or the
    score sits too close to the decision threshold, the service returns
    ABSTAIN. `unmapped` is a data state, not a category a model can be trained
    to predict — training a class for "I do not know" teaches the model the
    statistical signature of the rows that happened to be unlabelled, which is
    a property of the annotation process rather than of the traffic.
"""
