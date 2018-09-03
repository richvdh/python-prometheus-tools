#!/usr/bin/env python
#
# prints the metric name and labels for each known series file

from six import PY2

from prometheus_tools import *

fingerprint_to_labels = {}

def print_unicode(u):
    if PY2:
        # this gives a repr on python3
        print(u.encode("utf-8"))
    else:
        # ... but this fails on python2 when stdout is a pipe
        # because it thinks that stdout should be ascii
        print(u)

for (labelname, labelval), fps in read_labels_to_metrics_index():
    for fp in fps:
        s = fingerprint_to_labels.setdefault(fp, {})
        s[labelname]=labelval

for fp, labels in sorted(fingerprint_to_labels.items()):
    series = stringify_labelled_metric(labels)
    print_unicode(u"%016x\t%s" % (fp, series))
