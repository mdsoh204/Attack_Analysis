"""CICIDS DDoS classifier with bidirectional rolling flow features."""
import os
import threading
import time
from collections import OrderedDict, deque

np = None  # Loaded only after the user enables AI.

FEATURES = [
    " Destination Port", " Flow Duration", " Total Fwd Packets", " Total Backward Packets",
    "Total Length of Fwd Packets", " Total Length of Bwd Packets", " Fwd Packet Length Max",
    " Fwd Packet Length Min", " Fwd Packet Length Mean", " Fwd Packet Length Std",
    " Bwd Packet Length Max", " Bwd Packet Length Min", " Bwd Packet Length Mean",
    " Bwd Packet Length Std", " Flow Bytes/s", " Flow Packets/s", " Flow IAT Mean",
    " Flow IAT Std", " Flow IAT Max", " Flow IAT Min", " Fwd Packets/s", " Bwd Packets/s",
    " Min Packet Length", " Max Packet Length", " Packet Length Mean", " Packet Length Std",
    " Packet Length Variance", "FIN Flag Count", " SYN Flag Count", " RST Flag Count",
    " PSH Flag Count", " ACK Flag Count", " URG Flag Count", " Down/Up Ratio",
    " Average Packet Size", " Subflow Fwd Packets", " Subflow Fwd Bytes",
    " Subflow Bwd Packets", " Subflow Bwd Bytes", " act_data_pkt_fwd",
]
MODEL_VERSION = 2
FLOW_WINDOW_SECONDS = 60.0
MAX_FLOW_PACKETS = 512
MAX_TRACKED_FLOWS = 12000


class AIDetector:
    def __init__(self, dataset_path):
        self.dataset_path = os.path.abspath(dataset_path)
        self.cache_path = os.path.join(os.path.dirname(__file__), "model_cache", "cicids_ddos.joblib")
        self.model = None
        self.columns = []
        self.enabled = False
        self.loading = False
        self.error = ""
        self.model_quality = {}
        self._lock = threading.RLock()
        self._flows = OrderedDict()
        self._counts = {"analyzed": 0, "safe": 0, "threat": 0}

    def _load_or_train(self):
        global np
        import joblib
        import numpy as np
        import pandas as pd
        from sklearn.ensemble import ExtraTreesClassifier
        from sklearn.metrics import accuracy_score, f1_score
        from sklearn.model_selection import train_test_split

        if not os.path.isfile(self.dataset_path):
            raise FileNotFoundError("CICIDS dataset not found: " + self.dataset_path)
        stat = os.stat(self.dataset_path)
        signature = {"version": MODEL_VERSION, "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
        if os.path.isfile(self.cache_path):
            try:
                cached = joblib.load(self.cache_path)
                if cached.get("signature") == signature:
                    return cached["model"], cached["columns"], cached.get("quality", {})
            except Exception:
                pass

        header = pd.read_csv(self.dataset_path, nrows=0).columns
        normalized = {str(name).strip(): name for name in header}
        if "Label" not in normalized:
            raise ValueError("The dataset must have a Label column")
        feature_names = [name.strip() for name in FEATURES if name.strip() in normalized]
        if len(feature_names) < 15:
            raise ValueError("The dataset has too few supported CICIDS flow features")
        usecols = [normalized[name] for name in feature_names] + [normalized["Label"]]
        frame = pd.read_csv(self.dataset_path, usecols=usecols, low_memory=False)
        frame.columns = [str(name).strip() for name in frame.columns]
        labels = frame["Label"].astype(str).str.strip()
        valid = labels.ne("") & labels.str.lower().ne("nan")
        frame, labels = frame.loc[valid], labels.loc[valid]
        if labels.nunique() < 2:
            raise ValueError("The dataset needs at least two traffic labels to train a classifier")

        per_class = min(25000, int(labels.value_counts().min()))
        sampled = labels.groupby(labels).sample(n=per_class, random_state=42).index
        frame, labels = frame.loc[sampled], labels.loc[sampled]
        x = (frame[feature_names].apply(pd.to_numeric, errors="coerce")
             .replace([np.inf, -np.inf], np.nan).fillna(0.0))
        x = np.clip(x.to_numpy(dtype=np.float32), -1e9, 1e9)
        y = labels.to_numpy()
        x_train, x_valid, y_train, y_valid = train_test_split(
            x, y, test_size=0.2, random_state=42, stratify=y
        )
        params = dict(n_estimators=80, max_depth=20, min_samples_leaf=2,
                      max_features=0.9, n_jobs=-1, random_state=42)
        assessment = ExtraTreesClassifier(**params, class_weight="balanced")
        assessment.fit(x_train, y_train)
        predicted = assessment.predict(x_valid)
        quality = {
            "holdout_accuracy_pct": round(float(accuracy_score(y_valid, predicted)) * 100, 1),
            "holdout_macro_f1_pct": round(float(f1_score(y_valid, predicted, average="macro")) * 100, 1),
            "training_rows": int(len(x)),
            "labels": sorted(str(label) for label in np.unique(y)),
        }
        model = ExtraTreesClassifier(**params, class_weight="balanced")
        model.fit(x, y)
        os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
        temp_path = self.cache_path + ".tmp"
        joblib.dump({"signature": signature, "model": model, "columns": feature_names,
                     "quality": quality}, temp_path, compress=1)
        os.replace(temp_path, self.cache_path)
        return model, feature_names, quality

    def set_enabled(self, enabled):
        if enabled:
            with self._lock:
                if self.model is not None:
                    self.enabled = True
                    return self.status()
                self.loading, self.error = True, ""
            try:
                model, columns, quality = self._load_or_train()
                with self._lock:
                    self.model, self.columns, self.model_quality = model, columns, quality
                    self.enabled, self.loading = True, False
            except Exception as exc:
                with self._lock:
                    self.enabled, self.loading, self.error = False, False, str(exc)
                raise
        else:
            with self._lock:
                self.enabled = False
        return self.status()

    @staticmethod
    def _endpoint(ip, port):
        return (str(ip or ""), int(port or 0))

    def _flow_for(self, pkt, now):
        src = self._endpoint(pkt.get("src_ip"), pkt.get("src_port"))
        dst = self._endpoint(pkt.get("dst_ip"), pkt.get("dst_port"))
        key = (tuple(sorted((src, dst))), str(pkt.get("proto", "")))
        flow = self._flows.get(key)
        if flow is None or (flow["rows"] and now - flow["rows"][-1][0] > FLOW_WINDOW_SECONDS):
            flow = {"initiator": src, "destination_port": dst[1], "rows": deque(maxlen=MAX_FLOW_PACKETS)}
            self._flows[key] = flow
        self._flows.move_to_end(key)
        flow["rows"].append((now, max(0, int(pkt.get("size", 0))),
                             str(pkt.get("flags", "")), src == flow["initiator"]))
        while len(self._flows) > MAX_TRACKED_FLOWS:
            self._flows.popitem(last=False)
        return flow

    def score(self, pkt):
        with self._lock:
            if not self.enabled or self.model is None:
                return {"ai_enabled": False, "threat_pct": None, "safe_pct": None,
                        "attack_type": "Not analyzed", "ai_band": "off"}
            now = float(pkt.get("timestamp", time.time()))
            flow = self._flow_for(pkt, now)
            rows = list(flow["rows"])
            fwd = [row for row in rows if row[3]]
            bwd = [row for row in rows if not row[3]]
            sizes = np.asarray([row[1] for row in rows], dtype=np.float32)
            fs = np.asarray([row[1] for row in fwd], dtype=np.float32)
            bs = np.asarray([row[1] for row in bwd], dtype=np.float32)
            times = np.asarray([row[0] for row in rows], dtype=np.float64)
            duration = max(1e-6, float(times[-1] - times[0]))
            iat = np.diff(times) * 1e6 if len(times) > 1 else np.asarray([0.0])
            nf, nb = len(fwd), len(bwd)
            fb, bb = float(fs.sum()), float(bs.sum())
            flags = {flag: sum(flag in row[2] for row in rows) for flag in "FSRPAU"}
            values = {
                " Destination Port": int(flow["destination_port"]),
                " Flow Duration": duration * 1e6,
                " Total Fwd Packets": nf, " Total Backward Packets": nb,
                "Total Length of Fwd Packets": fb, " Total Length of Bwd Packets": bb,
                " Fwd Packet Length Max": float(fs.max()) if fs.size else 0,
                " Fwd Packet Length Min": float(fs.min()) if fs.size else 0,
                " Fwd Packet Length Mean": float(fs.mean()) if fs.size else 0,
                " Fwd Packet Length Std": float(fs.std()) if fs.size else 0,
                " Bwd Packet Length Max": float(bs.max()) if bs.size else 0,
                " Bwd Packet Length Min": float(bs.min()) if bs.size else 0,
                " Bwd Packet Length Mean": float(bs.mean()) if bs.size else 0,
                " Bwd Packet Length Std": float(bs.std()) if bs.size else 0,
                " Flow Bytes/s": (fb + bb) / duration, " Flow Packets/s": len(rows) / duration,
                " Flow IAT Mean": float(iat.mean()), " Flow IAT Std": float(iat.std()),
                " Flow IAT Max": float(iat.max()), " Flow IAT Min": float(iat.min()),
                " Fwd Packets/s": nf / duration, " Bwd Packets/s": nb / duration,
                " Min Packet Length": float(sizes.min()) if sizes.size else 0,
                " Max Packet Length": float(sizes.max()) if sizes.size else 0,
                " Packet Length Mean": float(sizes.mean()) if sizes.size else 0,
                " Packet Length Std": float(sizes.std()) if sizes.size else 0,
                " Packet Length Variance": float(sizes.var()) if sizes.size else 0,
                "FIN Flag Count": flags["F"], " SYN Flag Count": flags["S"],
                " RST Flag Count": flags["R"], " PSH Flag Count": flags["P"],
                " ACK Flag Count": flags["A"], " URG Flag Count": flags["U"],
                " Down/Up Ratio": nb / max(1, nf),
                " Average Packet Size": float(sizes.mean()) if sizes.size else 0,
                " Subflow Fwd Packets": nf, " Subflow Fwd Bytes": fb,
                " Subflow Bwd Packets": nb, " Subflow Bwd Bytes": bb,
                " act_data_pkt_fwd": nf,
            }
            normalized_values = {name.strip(): value for name, value in values.items()}
            vector = np.asarray([[normalized_values.get(name, 0.0) for name in self.columns]], dtype=np.float32)
            vector = np.nan_to_num(vector, nan=0.0, posinf=1e9, neginf=0.0)
            probs = self.model.predict_proba(vector)[0]
            classes = self.model.classes_
            benign_i = next((i for i, name in enumerate(classes)
                             if str(name).strip().upper() == "BENIGN"), None)
            threat = int(round((1.0 - float(probs[benign_i])) * 100)) if benign_i is not None else 0
            attack = str(classes[int(np.argmax(probs))])
            threat = max(0, min(100, threat))
            band = "red" if threat >= 90 else "yellow" if threat >= 50 else "green"
            self._counts["analyzed"] += 1
            self._counts["threat" if threat >= 50 else "safe"] += 1
            return {"ai_enabled": True, "threat_pct": threat, "safe_pct": 100 - threat,
                    "attack_type": attack, "ai_band": band}

    def stats(self):
        with self._lock:
            return {"enabled": self.enabled, **self._counts}

    def status(self):
        return {**self.stats(), "loading": self.loading, "error": self.error,
                "dataset": os.path.basename(self.dataset_path),
                "model": "ExtraTrees CICIDS flow classifier" if self.model else "Not trained",
                "quality": dict(self.model_quality)}
