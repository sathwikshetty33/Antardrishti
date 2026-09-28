"""a numpy evaluator of lightgbm text models (the bundle's boosters), so inference needs no
lightgbm wheel and no system openmp library (app/CLAUDE.md section 4).

covers what the bundle uses: numerical splits with lightgbm's missing-value rules, and the
binary (sigmoid), cross_entropy (sigmoid) and multiclass (softmax) objectives. categorical
splits and linear trees are refused. tests check it against lightgbm itself.
"""
import numpy as np


class booster:
    def __init__(self, path=None, text=None):
        text = text if text is not None else open(path).read()
        head, _, body = text.partition("\nTree=")
        kv = dict(l.split("=", 1) for l in head.splitlines() if "=" in l)
        self.nclass = int(kv.get("num_tree_per_iteration", 1))
        self.nfeat = int(kv["max_feature_idx"]) + 1
        self.names = kv.get("feature_names", "").split()
        obj = kv.get("objective", "").split()
        self.objective = obj[0] if obj else ""
        self.sigmoid = float(next((o.split(":")[1] for o in obj if o.startswith("sigmoid:")), 1.0))
        if self.objective not in ("binary", "cross_entropy", "multiclass", "regression"):
            raise ValueError(f"unsupported objective {self.objective}")
        self.trees = []
        for block in ("Tree=" + body).split("\nTree=")[:]:
            block = block.split("end of trees")[0]
            t = dict(l.split("=", 1) for l in block.splitlines() if "=" in l)
            if "num_leaves" not in t:
                continue
            if int(t.get("num_cat", 0)) or t.get("is_linear", "0") != "0":
                raise ValueError("categorical or linear trees are not supported")
            leaf = np.array(t["leaf_value"].split(), float)
            if int(t["num_leaves"]) == 1:
                self.trees.append({"leaf": leaf})
                continue
            self.trees.append({
                "feat": np.array(t["split_feature"].split(), int),
                "thr": np.array(t["threshold"].split(), float),
                "dt": np.array(t["decision_type"].split(), int),
                "left": np.array(t["left_child"].split(), int),
                "right": np.array(t["right_child"].split(), int),
                "leaf": leaf})

    def num_feature(self):
        return self.nfeat

    def feature_name(self):
        return self.names

    def raw(self, X):
        X = np.asarray(X, float)
        n = len(X)
        out = np.zeros((n, self.nclass))
        rows = np.arange(n)
        for i, t in enumerate(self.trees):
            if "feat" not in t:
                out[:, i % self.nclass] += t["leaf"][0]
                continue
            node = np.zeros(n, int)
            live = np.ones(n, bool)
            while live.any():
                nd = node[live]
                x = X[rows[live], t["feat"][nd]]
                dt = t["dt"][nd]
                miss = (dt >> 2) & 3
                default_left = (dt & 2) > 0
                nan = np.isnan(x)
                x = np.where(nan & (miss != 2), 0.0, x)
                use_default = ((miss == 1) & (np.abs(x) <= 1e-35)) | ((miss == 2) & nan)
                go_left = np.where(use_default, default_left, x <= t["thr"][nd])
                node[live] = np.where(go_left, t["left"][nd], t["right"][nd])
                live = node >= 0
            out[:, i % self.nclass] += t["leaf"][~node]
        return out

    def predict(self, X):
        r = self.raw(X)
        if self.objective == "multiclass":
            e = np.exp(r - r.max(1, keepdims=True))
            return e / e.sum(1, keepdims=True)
        if self.objective in ("binary", "cross_entropy"):
            s = self.sigmoid if self.objective == "binary" else 1.0
            return 1 / (1 + np.exp(-s * r[:, 0]))
        return r[:, 0]
