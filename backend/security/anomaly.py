"""
anomaly.py — IsolationForest Behavioral Anomaly Detector (Member B / FR-4).

Trains a deterministic Isolation Forest on synthetic normal file-activity
windows (including benign bulk edits and routine archive writes to minimize
false positives), scores live activity windows, explains feature deviations
via z-scores, and provides false-positive evaluation metrics.

Uses `scikit-learn` (`IsolationForest` + `StandardScaler`) when available, and
falls back automatically to a faithful pure-Python Isolation Forest (Liu, Ting
& Zhou, 2008) if compiled `sklearn` extensions cannot load in restricted
environments.
"""

from __future__ import annotations

import math
import random
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    from sklearn.ensemble import IsolationForest as _SklearnIsolationForest
    from sklearn.preprocessing import StandardScaler as _SklearnStandardScaler

    _SKLEARN_AVAILABLE = True
except (ImportError, OSError):
    _SKLEARN_AVAILABLE = False

MODEL_VERSION: str = (
    "IsolationForest-sklearn-v1.0"
    if _SKLEARN_AVAILABLE
    else "IsolationForest-pure-v1.0"
)

FEATURE_NAMES: List[str] = [
    "event_rate",
    "modify_count",
    "rename_count",
    "delete_count",
    "create_count",
    "mean_entropy",
    "max_entropy",
    "mean_entropy_delta",
    "suspicious_ext_ratio",
]


def _harmonic_number(n: int) -> float:
    if n <= 0:
        return 0.0
    return math.log(n) + 0.5772156649


def _c_factor(n: int) -> float:
    """Average path length of unsuccessful search in a BST (Liu et al., 2008)."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * _harmonic_number(n - 1) - (2.0 * (n - 1) / n)


class _PureIsolationTree:
    """Single randomized binary isolation tree."""

    def __init__(self, max_depth: int, rng: random.Random) -> None:
        self.max_depth = max_depth
        self.rng = rng
        self.root: Optional[Tuple[Any, ...]] = None

    def fit(self, rows: List[List[float]]) -> None:
        self.root = self._build(rows, depth=0)

    def _build(self, rows: List[List[float]], depth: int) -> Tuple[Any, ...]:
        n = len(rows)
        if depth >= self.max_depth or n <= 1:
            return ("leaf", n)

        n_dims = len(rows[0])
        dims = list(range(n_dims))
        self.rng.shuffle(dims)

        for dim in dims:
            col = [r[dim] for r in rows]
            lo, hi = min(col), max(col)
            if hi > lo:
                split = self.rng.uniform(lo, hi)
                left = [r for r in rows if r[dim] < split]
                right = [r for r in rows if r[dim] >= split]
                if left and right:
                    return (
                        "node",
                        dim,
                        split,
                        self._build(left, depth + 1),
                        self._build(right, depth + 1),
                    )
        return ("leaf", n)

    def path_length(self, row: List[float]) -> float:
        node = self.root
        depth = 0
        while node is not None:
            if node[0] == "leaf":
                return float(depth) + _c_factor(int(node[1]))
            _, dim, split, left, right = node
            node = left if row[dim] < split else right
            depth += 1
        return float(depth)


class _PureIsolationForest:
    """Pure-Python Isolation Forest matching scikit-learn's predict/decision API."""

    def __init__(
        self,
        n_estimators: int = 100,
        contamination: float = 0.03,
        random_state: int = 42,
        max_samples: int = 256,
    ) -> None:
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.max_samples = max_samples
        self._trees: List[_PureIsolationTree] = []
        self._c_n: float = 1.0
        self._offset: float = 0.5

    def fit(self, matrix: List[List[float]]) -> "_PureIsolationForest":
        rng = random.Random(self.random_state)
        n_rows = len(matrix)
        psi = min(self.max_samples, n_rows)
        max_depth = max(1, int(math.ceil(math.log2(max(psi, 2)))))
        self._c_n = max(_c_factor(psi), 1e-6)
        self._trees = []

        for _ in range(self.n_estimators):
            sample = rng.sample(matrix, psi) if n_rows > psi else list(matrix)
            tree = _PureIsolationTree(max_depth=max_depth, rng=rng)
            tree.fit(sample)
            self._trees.append(tree)

        # Calibrate decision boundary at the (1 - contamination) quantile
        raw_scores = sorted(self._anomaly_score_raw(row) for row in matrix)
        idx = min(
            len(raw_scores) - 1,
            max(0, int((1.0 - self.contamination) * len(raw_scores))),
        )
        self._offset = raw_scores[idx]
        return self

    def _anomaly_score_raw(self, row: List[float]) -> float:
        avg_path = sum(t.path_length(row) for t in self._trees) / len(self._trees)
        return math.pow(2.0, -avg_path / self._c_n)

    def decision_function(self, matrix: List[List[float]]) -> List[float]:
        # Positive = normal, negative = anomaly (mirrors sklearn IsolationForest)
        return [self._offset - self._anomaly_score_raw(row) for row in matrix]

    def predict(self, matrix: List[List[float]]) -> List[int]:
        return [-1 if score < 0.0 else 1 for score in self.decision_function(matrix)]


class _PureStandardScaler:
    """Minimal pure-Python standard scaler."""

    def __init__(self) -> None:
        self.means: List[float] = []
        self.stds: List[float] = []

    def fit_transform(self, matrix: List[List[float]]) -> List[List[float]]:
        n_rows = len(matrix)
        n_cols = len(matrix[0])
        self.means = [
            sum(row[c] for row in matrix) / n_rows for c in range(n_cols)
        ]
        self.stds = []
        for c in range(n_cols):
            var = sum((row[c] - self.means[c]) ** 2 for row in matrix) / n_rows
            std = math.sqrt(var)
            self.stds.append(std if std > 1e-9 else 1.0)
        return self.transform(matrix)

    def transform(self, matrix: List[List[float]]) -> List[List[float]]:
        return [
            [(row[c] - self.means[c]) / self.stds[c] for c in range(len(row))]
            for row in matrix
        ]


def generate_normal_training_samples(
    n_samples: int = 300,
    random_state: int = 42,
) -> List[Dict[str, float]]:
    """
    Generate realistic synthetic normal file-activity window feature dicts.

    Covers three benign profiles so normal bursts (e.g., saving documents or
    benign bulk copies/archives) do not trigger unnecessary false positives:
      1. Routine single-file editing (70%)
      2. Benign bulk copy / IDE build / batch save with low entropy delta (20%)
      3. Occasional compressed archive write without bulk renames/deletes (10%)
    """
    rng = random.Random(random_state)
    samples: List[Dict[str, float]] = []

    n_routine = int(n_samples * 0.70)
    n_bulk = int(n_samples * 0.20)
    n_archive = n_samples - n_routine - n_bulk

    # 1. Routine editing
    for _ in range(n_routine):
        mod_c = rng.randint(0, 3)
        cre_c = rng.randint(0, 2)
        del_c = rng.randint(0, 1)
        ren_c = rng.randint(0, 1)
        total = max(1, mod_c + cre_c + del_c + ren_c)
        mean_ent = rng.uniform(3.0, 5.6)
        max_ent = min(6.4, mean_ent + rng.uniform(0.0, 0.7))
        delta = rng.uniform(-0.3, 0.45)
        samples.append(
            {
                "event_rate": round(total / 10.0, 4),
                "modify_count": float(mod_c),
                "rename_count": float(ren_c),
                "delete_count": float(del_c),
                "create_count": float(cre_c),
                "mean_entropy": round(mean_ent, 4),
                "max_entropy": round(max_ent, 4),
                "mean_entropy_delta": round(delta, 4),
                "suspicious_ext_ratio": 0.0,
            }
        )

    # 2. Benign bulk operations (e.g., copying folder, saving project assets)
    for _ in range(n_bulk):
        cre_c = rng.randint(3, 9)
        mod_c = rng.randint(0, 3)
        del_c = rng.randint(0, 1)
        ren_c = rng.randint(0, 1)
        total = cre_c + mod_c + del_c + ren_c
        mean_ent = rng.uniform(3.2, 5.8)
        max_ent = min(6.5, mean_ent + rng.uniform(0.1, 0.6))
        delta = rng.uniform(0.0, 0.35)
        samples.append(
            {
                "event_rate": round(total / 10.0, 4),
                "modify_count": float(mod_c),
                "rename_count": float(ren_c),
                "delete_count": float(del_c),
                "create_count": float(cre_c),
                "mean_entropy": round(mean_ent, 4),
                "max_entropy": round(max_ent, 4),
                "mean_entropy_delta": round(delta, 4),
                "suspicious_ext_ratio": 0.0,
            }
        )

    # 3. Normal compressed archive / media save (higher baseline entropy, low rename/delete)
    for _ in range(n_archive):
        cre_c = rng.randint(1, 2)
        mod_c = rng.randint(0, 1)
        total = cre_c + mod_c
        mean_ent = rng.uniform(6.0, 7.2)
        max_ent = rng.uniform(6.8, 7.45)
        delta = rng.uniform(0.0, 0.5)
        samples.append(
            {
                "event_rate": round(total / 10.0, 4),
                "modify_count": float(mod_c),
                "rename_count": 0.0,
                "delete_count": 0.0,
                "create_count": float(cre_c),
                "mean_entropy": round(mean_ent, 4),
                "max_entropy": round(max_ent, 4),
                "mean_entropy_delta": round(delta, 4),
                "suspicious_ext_ratio": 0.0,
            }
        )

    return samples


def extract_features(window_stats: Dict[str, Any]) -> List[float]:
    """Extract sanitized 9-feature vector from a window statistics dictionary."""
    vector: List[float] = []
    for name in FEATURE_NAMES:
        raw = window_stats.get(name, 0.0)
        try:
            val = float(raw)
        except (TypeError, ValueError):
            val = 0.0
        if not math.isfinite(val):
            val = 0.0
        vector.append(val)
    return vector


class AnomalyDetector:
    """
    Explainable IsolationForest anomaly detector for file-activity time windows.
    """

    def __init__(
        self,
        contamination: float = 0.03,
        random_state: int = 42,
        auto_fit: bool = True,
    ) -> None:
        self.contamination = float(contamination)
        self.random_state = int(random_state)
        if _SKLEARN_AVAILABLE:
            self._scaler = _SklearnStandardScaler()
            self._model = _SklearnIsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                random_state=self.random_state,
            )
        else:
            self._scaler = _PureStandardScaler()
            self._model = _PureIsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                random_state=self.random_state,
            )
        self._feature_means: List[float] = []
        self._feature_stds: List[float] = []
        self._is_fitted = False
        self._lock = threading.Lock()

        if auto_fit:
            self.fit(generate_normal_training_samples(random_state=self.random_state))

    def fit(self, samples: Optional[List[Dict[str, Any]]] = None) -> "AnomalyDetector":
        """Train scaler and IsolationForest on normal baseline window samples."""
        data = samples if samples is not None else generate_normal_training_samples(
            random_state=self.random_state
        )
        if not data:
            raise ValueError("Cannot fit AnomalyDetector on empty sample list")

        matrix = [extract_features(s) for s in data]
        n_rows = len(matrix)
        n_cols = len(FEATURE_NAMES)

        means = [sum(row[c] for row in matrix) / n_rows for c in range(n_cols)]
        stds = []
        for c in range(n_cols):
            var = sum((row[c] - means[c]) ** 2 for row in matrix) / n_rows
            stds.append(max(math.sqrt(var), 0.05))

        with self._lock:
            scaled = self._scaler.fit_transform(matrix)
            self._model.fit(scaled)
            self._feature_means = means
            self._feature_stds = stds
            self._is_fitted = True
        return self

    def score_window(self, window_stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Score an activity window and return explainable anomaly metrics.
        """
        if not self._is_fitted:
            raise RuntimeError("AnomalyDetector must be fitted before scoring")

        vec = [extract_features(window_stats)]
        with self._lock:
            scaled = self._scaler.transform(vec)
            pred = int(self._model.predict(scaled)[0])  # -1 = anomaly, 1 = normal
            raw_decision = float(self._model.decision_function(scaled)[0])
            means = list(self._feature_means)
            stds = list(self._feature_stds)

        is_anomaly = pred == -1

        # Map decision_function (negative = outlier, positive = normal) to 0..100 risk
        normalized_risk = (0.12 - raw_decision) / 0.37 * 100.0
        risk_score = round(min(100.0, max(0.0, normalized_risk)), 2)
        if is_anomaly and risk_score < 60.0:
            risk_score = 60.0
        if not is_anomaly and risk_score >= 65.0:
            risk_score = 55.0

        # Compute per-feature positive z-score deviations for explainability
        deviations: List[Dict[str, float | str]] = []
        for idx, fname in enumerate(FEATURE_NAMES):
            obs = vec[0][idx]
            mean_val = means[idx]
            std_val = stds[idx]
            z = (obs - mean_val) / std_val
            if z > 1.5:
                deviations.append(
                    {
                        "feature": fname,
                        "observed": round(obs, 4),
                        "baseline_mean": round(mean_val, 4),
                        "z_score": round(z, 2),
                    }
                )

        deviations.sort(key=lambda d: float(d["z_score"]), reverse=True)
        top_deviations = deviations[:3]

        if risk_score >= 85.0:
            severity = "CRITICAL"
        elif risk_score >= 65.0:
            severity = "HIGH"
        elif risk_score >= 35.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        evidence: List[str] = []
        if is_anomaly:
            if top_deviations:
                summary = ", ".join(
                    f"{d['feature']}={d['observed']} (baseline {d['baseline_mean']}, z={d['z_score']})"
                    for d in top_deviations
                )
                evidence.append(
                    f"{MODEL_VERSION} flagged anomalous behavior (risk={risk_score:.1f}): {summary}"
                )
            else:
                evidence.append(
                    f"{MODEL_VERSION} flagged anomalous joint feature pattern (risk={risk_score:.1f})"
                )
        else:
            evidence.append(
                f"{MODEL_VERSION} classified activity window as normal (risk={risk_score:.1f})"
            )

        return {
            "module": "anomaly",
            "is_anomaly": is_anomaly,
            "raw_decision_score": round(raw_decision, 4),
            "risk_score": risk_score,
            "severity": severity,
            "top_deviations": top_deviations,
            "evidence": evidence,
            "model_version": MODEL_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def evaluate_false_positives(
        self,
        normal_samples: List[Dict[str, Any]],
        anomalous_samples: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Measure false positive rate on normal samples and (optionally) detection
        rate, false negative rate, and average inference latency on anomalous samples.
        """
        if not normal_samples:
            raise ValueError("normal_samples cannot be empty")

        start = time.perf_counter()
        fp_count = 0
        for sample in normal_samples:
            if self.score_window(sample)["is_anomaly"]:
                fp_count += 1
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        total_normal = len(normal_samples)
        fpr = round(fp_count / total_normal, 4)

        report: Dict[str, Any] = {
            "model_version": MODEL_VERSION,
            "total_normal": total_normal,
            "false_positives": fp_count,
            "false_positive_rate": fpr,
            "avg_latency_ms": round(elapsed_ms / total_normal, 4),
        }

        if anomalous_samples:
            tp_count = 0
            for sample in anomalous_samples:
                if self.score_window(sample)["is_anomaly"]:
                    tp_count += 1
            total_anom = len(anomalous_samples)
            fn_count = total_anom - tp_count
            report.update(
                {
                    "total_anomalous": total_anom,
                    "true_positives": tp_count,
                    "false_negatives": fn_count,
                    "true_positive_rate": round(tp_count / total_anom, 4),
                    "false_negative_rate": round(fn_count / total_anom, 4),
                }
            )

        return report
