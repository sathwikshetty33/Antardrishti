"""training helpers shared by the config and traffic models: grouped folds, early stopping,
isotonic calibration, thresholds, ece. every fold, split and booster uses the analyzer seed."""
import lightgbm as lgb
import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold, GroupKFold

from analyzer import common as cm
from analyzer.calib import iso, iso_multi  # noqa: F401 (shared with inference)

threads = 4
base = {"learning_rate": 0.05, "num_leaves": 15, "min_data_in_leaf": 10, "feature_fraction": 0.8,
        "bagging_fraction": 0.8, "bagging_freq": 1, "lambda_l2": 1.0, "verbose": -1,
        "num_threads": threads, "seed": cm.seed, "deterministic": True, "force_row_wise": True}
max_rounds = 2000
patience = 50


def folds(y, groups, k=5):
    """k grouped folds, stratified when y is a class label"""
    ug = np.unique(groups)
    k = min(k, len(ug))
    try:
        cv = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=cm.seed)
        return list(cv.split(np.zeros(len(y)), y, groups))
    except ValueError:
        return list(GroupKFold(n_splits=k).split(np.zeros(len(y)), y, groups))


def params(objective, nclass=None, weight=None):
    p = dict(base, objective=objective)
    if nclass:
        p["num_class"] = nclass
    return p


def fit(X, y, groups, p, w=None, rounds=None):
    """one booster; with rounds None, early stopping on a grouped 20% validation split"""
    if rounds is None:
        gs = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=cm.seed)
        tr, va = next(gs.split(X, y, groups))
        dtr = lgb.Dataset(X[tr], y[tr], weight=None if w is None else w[tr], free_raw_data=False)
        dva = lgb.Dataset(X[va], y[va], weight=None if w is None else w[va], reference=dtr)
        b = lgb.train(p, dtr, max_rounds, valid_sets=[dva],
                      callbacks=[lgb.early_stopping(patience, verbose=False)])
        return b, b.best_iteration or max_rounds
    b = lgb.train(p, lgb.Dataset(X, y, weight=w), rounds)
    return b, rounds


def oof(X, y, groups, p, w=None, strat=None):
    """out-of-fold predictions over 5 grouped folds, then a final booster on all rows with the
    median best round count. -> (final booster, oof predictions, rounds, fold ids)"""
    fs = folds(strat if strat is not None else y, groups)
    shape = (len(y), p["num_class"]) if p.get("num_class") else (len(y),)
    pred = np.zeros(shape)
    fold_id = np.zeros(len(y), int)
    its = []
    for i, (tr, te) in enumerate(fs):
        b, it = fit(X[tr], y[tr], groups[tr], p, None if w is None else w[tr])
        pred[te] = b.predict(X[te], num_iteration=it)
        fold_id[te] = i
        its.append(it)
    rounds = int(np.median(its))
    final, _ = fit(X, y, groups, p, w, rounds=rounds)
    return final, pred, rounds, fold_id


def balanced(y):
    """class_weight balanced as sample weights"""
    y = np.asarray(y)
    w = np.ones(len(y))
    for c in np.unique(y):
        w[y == c] = len(y) / (len(np.unique(y)) * (y == c).sum())
    return w


def iso_fit(p, y):
    if len(np.unique(y)) < 2:
        return {"x": [0.0, 1.0], "y": [float(np.mean(y))] * 2}
    r = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit(p, y)
    return {"x": r.X_thresholds_.tolist(), "y": r.y_thresholds_.tolist()}


def best_threshold(p, y):
    """threshold maximising f1"""
    best, bt = -1.0, 0.5
    for t in np.unique(np.round(p, 4)):
        pr = p >= t
        tp = (pr & (y == 1)).sum()
        f = 2 * tp / (pr.sum() + (y == 1).sum()) if pr.sum() + (y == 1).sum() else 0
        if f > best:
            best, bt = f, float(t)
    return bt, float(best)


def ece(p, y, bins=10):
    """expected calibration error and the reliability curve (binary)"""
    p, y = np.asarray(p, float), np.asarray(y, float)
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges) - 1, 0, bins - 1)
    e, curve = 0.0, []
    for b in range(bins):
        m = idx == b
        if m.any():
            e += m.mean() * abs(p[m].mean() - y[m].mean())
            curve.append((float(p[m].mean()), float(y[m].mean()), int(m.sum())))
    return float(e), curve


def gains(b, names, top=15):
    g = b.feature_importance("gain")
    tot = g.sum() or 1
    o = np.argsort(-g)[:top]
    return [(names[i], float(g[i] / tot)) for i in o]
