import itertools
import leveldb
import struct

# all of the decodeXXX functions return a (result, pos) tuple.
#
# the prometheus format is based on protobufs, though the impls here are largely
# revenged from https://github.com/prometheus/prometheus/blob/release-1.8/storage/local/codable/codable.go

def decodeUVarint(buffer, pos=0):
    result = 0
    shift = 0
    while 1:
        b = buffer[pos]
        result |= ((b & 0x7f) << shift)
        pos += 1
        if not (b & 0x80):
            return (result, pos)
        shift += 7
        if shift >= 64:
            raise _DecodeError('Too many bytes when decoding varint.')

def decodeVarint(buffer, pos=0):
    result, pos = decodeUVarint(buffer, pos)
    if result & 1:
        result = -((result+1) >> 1)
    else:
        result = result >> 1
    return result, pos

def encodeVarint(i):
    orig = i
    res = bytearray()
    if i < 0:
        i = (-i << 1) - 1
    else:
        i = i << 1
    while i > 0x7f:
        res.append((i & 0x7f) | 0x80)
        i >>= 7
    res.append(i)
    res = bytearray(reversed(res))
    return res

def decodeString(buffer, pos=0):
    length, pos = decodeVarint(buffer, pos)
    end = pos+length
    result = buffer[pos:end].decode('utf-8')
    return result, end

def encodeString(string):
    buf = string.encode('utf-8')
    l = encodeVarint(len(buf))
    return l + buf

def decodeUint64(buffer, pos=0):
    res, = struct.unpack_from('>Q', buffer, pos)
    return res, pos+8

def decodeFingerprints(buffer, pos=0):
    numfps, pos = decodeVarint(buffer, pos)
    res=[]
    for i in range(0, numfps):
        fp, pos = decodeUint64(buffer, pos)
        res.append(fp)
    return res, pos

def decodeLabelPair(buffer, pos=0):
    """decode a name=val label pair

    Returns: ((str, str), int)
    """
    name, pos = decodeString(buffer, pos)
    value, pos = decodeString(buffer, pos)
    return ((name, value), pos)

def decodeMetric(buffer, pos=0):
    """decode a metric, which is stored as a series of name=val label pairs

    Returns: (dict[str, str], int)
    """
    numlabelpairs, pos = decodeVarint(buffer, pos)
    labels = {}
    for i in range(0, numlabelpairs):
        ((n, v), pos) = decodeLabelPair(buffer, pos)
        labels[n] = v

    return labels, pos

def decodeLabelValues(buffer, pos=0):
    numvalues, pos = decodeVarint(buffer, pos)
    values = []
    for i in range(0, numvalues):
        val, pos = decodeString(buffer, pos)
        values.append(val)

    return values, pos

def read_fingerprint_metric_index(**kwargs):
    """archived_fingerprint_to_metric maps from fingerprint to labelled metric

    ... but only for old metrics.

    Args:
        kwargs: keyword args to pass to labeldb.RangeIter
    Returns:
        Iterable[(int, dict[str, str])]:
             iterable of (fingerprint, labeled metric) tuples
    """
    db = leveldb.LevelDB(
        'archived_fingerprint_to_metric',
        create_if_missing=False,
    )
    for (k, v) in db.RangeIter(**kwargs):
        fingerprint, _ = decodeUint64(bytearray(k))
        labels, _ = decodeMetric(bytearray(v))
        yield fingerprint, labels


def read_labels_to_metrics_index(**kwargs):
    """labelpair_to_fingerprints maps from a given (k=v) label pair to the
    fingerprints files which include that labelpair

    Args:
        kwargs: keyword args to pass to labeldb.RangeIter
    Returns:
        Iterable[(str, str), list[int]): ((key, val), fingerprints
    """
    db = leveldb.LevelDB('labelpair_to_fingerprints', create_if_missing=False)
    for (k, v) in db.RangeIter(**kwargs):
        label, _ = decodeLabelPair(bytearray(k))
        fps, _ = decodeFingerprints(bytearray(v))
        yield label, fps


def read_labelname_to_labelvalues_index(**kwargs):
    db = leveldb.LevelDB('labelname_to_labelvalues', create_if_missing=False)
    for (k, v) in db.RangeIter(**kwargs):
        label, _ = decodeString(bytearray(k))
        values, _ = decodeLabelValues(bytearray(v))
        yield label, values


def read_heads_db():
    """

    ref: https://github.com/prometheus/prometheus/blob/release-1.8/storage/local/heads.go#L93
    """
    with open('heads.db', 'rb') as f:
        data = bytearray(f.read())

    pos = 0
    magic = data[0:15]
    if magic != b'PrometheusHeads':
        raise Exception("bad magic")
    pos += 15

    ver, pos = decodeVarint(data, pos)
    count, pos = decodeUint64(data, pos)

    for i in range(0, count):
        flags = data[i:i]
        pos += 1
        fingerprint, pos = decodeUint64(data, pos)
        metric, pos = decodeMetric(data, pos)
        if ver != 1:
            wm, pos = decodeVarint(data, pos)
            mtime, pos = decodeVarint(data, pos)
        else:
            raise Exception("unimplemented: old heads db")
        descs_offset, pos = decodeVarint(data, pos)
        saved_first_time, pos = decodeVarint(data, pos)
        num_descs, pos = decodeVarint(data, pos)

        for i in range(0, num_descs):
            if i >= wm:
                raise Exception("unimplemented: unpersisted")
            first_time, pos = decodeVarint(data, pos)
            last_time, pos = decodeVarint(data, pos)

        print("%016x: %s" % (fingerprint, stringify_labelled_metric(metric)))


def stringify_labelled_metric(labels):
    """stringify a labelled metric

    labelled metrics are recorded as a series of label=val pairs, with the
    special __name__ label as the metric name.

    Args:
        labels (dict[str,str]):

    Returns:
        str
    """
    return "%s{%s}" % (
        labels["__name__"],
        ",".join(
            "%s=\"%s\"" % (k1,v1)

            # we sort the label names to keep the order stable.
            for k1, v1 in sorted(labels.items())
            if k1 != "__name__",
        )
    )
