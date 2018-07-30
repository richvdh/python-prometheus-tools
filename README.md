Prometheus management tools
---------------------------

A set of tools for reading the prometheus disk data.

Currently only supports the prometheus v1 storage engine.

It's suggested that you run this on *copies* of the prometheus metrics. Note
that the leveldb files can become inconsistent within seconds, so copy locally
before scpping rather than scpping the whole db directory.
