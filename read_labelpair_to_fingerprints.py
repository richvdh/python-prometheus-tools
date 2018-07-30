#!/usr/bin/env python
#
# prints the metric name and labels for each known series file

from prometheus_tools import *
from six import iteritems

fingerprint_to_labels = {}

for (labelname, labelval), fps in read_labels_to_metrics_index():
    for fp in fps:
        s = fingerprint_to_labels.setdefault(fp, {})
        s[labelname]=labelval

for fp, labels in iteritems(fingerprint_to_labels):
    print("%016x %s" % (
        fp, stringify_labelled_metric(labels),
    ))
