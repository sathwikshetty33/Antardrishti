"""isotonic calibration helpers used at inference: pure numpy (the calibrators are stored as
threshold arrays). fitting stays in ml.py, which needs scikit-learn."""
import numpy as np


def iso(c, p):
    return np.interp(p, c["x"], c["y"])


def iso_multi(cs, P):
    q = np.stack([iso(c, P[:, k]) for k, c in enumerate(cs)], 1)
    s = q.sum(1, keepdims=True)
    return np.where(s > 0, q / np.where(s > 0, s, 1), 1.0 / P.shape[1])
