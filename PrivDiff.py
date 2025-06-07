import os
import pwd
import stat
import subprocess
import plistlib
import json
import time
import random
import threading
import base64
import hashlib
import importlib.util
import glob
import yaml
from pathlib import Path
from collections import defaultdict, deque
from functools import lru_cache

class PrivDiff:
    def __init__(self):
        self.results = defaultdict(dict)
        self.timestamp = int(time.time())
        self.sys_entropy = random.getrandbits(512)
        self.hash_context = hashlib.sha256(str(self.sys_entropy).encode()).hexdigest()
        self.users = sorted({user.pw_name for user in pwd.getpwall() if int(user.pw_uid) >= 500 or user.pw_name == 'root'})
        self.user_uid_map = {user: pwd.getpwnam(user).pw_uid for user in self.users}
        self.lock = threading.RLock()
        self.trace_log = deque(maxlen=1000)
        self.rules = self._load_rules()
        self.cache_dir = Path(".privdiff_cache")
        self.cache_dir.mkdir(exist_ok=True)

    def _trace(self, event):
        with self.lock:
            self.trace_log.appendleft((time.time(), event))

    def _load_rules(self):
        rules_path = Path("rules.yml")
        if rules_path.exists():
            with open(rules_path) as f:
                return yaml.safe_load(f)
        return {}

    @lru_cache(maxsize=128)
    def _walk_paths(self, root_path):
        exclude_dirs = {'proc', 'dev', 'sys', 'Volumes', 'private'}
        for root, dirs, files in os.walk(root_path, topdown=True):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in exclude_dirs]
            for file in files:
                yield os.path.join(root, file)

    def _detect_suid(self):
        binaries = []
        for path in self._walk_paths("/"):
            try:
                st = os.stat(path)
                if st.st_mode & stat.S_ISUID:
                    binaries.append((path, st.st_uid, oct(st.st_mode)[-4:]))
                    self._trace(f"Detected SUID: {path}")
            except Exception as e:
                self._trace(f"SUID Check Failed: {path} [{str(e)}]")
        return binaries

    def _evaluate_suids(self, binaries):
        for user, uid in self.user_uid_map.items():
            for path, owner_uid, perms in binaries:
                try:
                    if os.access(path, os.W_OK) and uid != owner_uid:
                        risk_score = 100 if owner_uid != 0 else 60
                        self.results['suid_drifts'].setdefault(user, []).append({
                            "path": path,
                            "owner": pwd.getpwuid(owner_uid).pw_name,
                            "mode": perms,
                            "score": risk_score
                        })
                        self._trace(f"Writable SUID for {user}: {path}")
                except Exception as e:
                    self._trace(f"Evaluation Error: {path} [{str(e)}]")

    def _parse_crontabs(self):
        for user in self.users:
            try:
                output = subprocess.check_output(["crontab", "-l", "-u", user], stderr=subprocess.DEVNULL).decode()
                jobs = [line for line in output.strip().splitlines() if line and not line.startswith('#')]
                if jobs:
                    self.results['cron_jobs'][user] = jobs
                    self._trace(f"Cron found for {user}: {len(jobs)} job(s)")
            except Exception as e:
                self._trace(f"Cron parsing failed for {user}: {str(e)}")

    def _check_launch_items(self):
        paths = ["/Library/LaunchAgents", "/Library/LaunchDaemons", "/System/Library/LaunchAgents", str(Path.home() / "Library/LaunchAgents")]
        for d in paths:
            try:
                for f in os.listdir(d):
                    full = os.path.join(d, f)
                    if os.path.isfile(full):
                        try:
                            st = os.stat(full)
                            if st.st_uid != 0:
                                self.results['launchd_anomalies'].setdefault(d, []).append({
                                    "file": f,
                                    "owner": pwd.getpwuid(st.st_uid).pw_name
                                })
                                self._trace(f"Launch anomaly: {f} not owned by root")
                        except Exception as e:
                            self._trace(f"Launch item stat failed: {f} [{str(e)}]")
            except Exception as e:
                self._trace(f"Launch path access failed: {d} [{str(e)}]")

    def _load_modules(self):
        module_results = {}
        for path in glob.glob("modules/*.py"):
            name = Path(path).stem
            try:
                spec = importlib.util.spec_from_file_location(name, path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "run"):
                    module_results[name] = mod.run()
                    self._trace(f"Executed module: {name}")
            except Exception as e:
                self._trace(f"Module load failed: {name} [{str(e)}]")
        self.results['modules'] = module_results

    def _timed_run(self, func, label):
        start = time.time()
        func()
        duration = time.time() - start
        self.results['timing'] = self.results.get('timing', {})
        self.results['timing'][label] = round(duration, 4)
        self._trace(f"{label} took {duration:.3f}s")

    def run_all_checks(self):
        suids = self._detect_suid()
        self._timed_run(lambda: self._evaluate_suids(suids), 'suid_evaluation')
        self._timed_run(self._parse_crontabs, 'crontab_check')
        self._timed_run(self._check_launch_items, 'launchd_check')
        self._timed_run(self._load_modules, 'module_checks')
        self._diff_last_scan()

    def _diff_last_scan(self):
        current = self.results
        cache_file = self.cache_dir / "last.json"
        if cache_file.exists():
            try:
                with open(cache_file) as f:
                    old = json.load(f)
                diffs = {}
                for key in current:
                    if current[key] != old.get(key):
                        diffs[key] = {"current": current[key], "previous": old.get(key)}
                if diffs:
                    self.results['diffs'] = diffs
                    self._trace(f"Detected diffs from last scan")
            except Exception as e:
                self._trace(f"Diffing failed: {str(e)}")
        with open(cache_file, "w") as f:
            json.dump(current, f)

    def display_results(self):
        print("[+] Executing PrivDiff Recon")
        if 'suid_drifts' in self.results:
            print("\n[*] Writable SUID Binaries:")
            for user, entries in self.results['suid_drifts'].items():
                print(f"\n[!] {user}:")
                for e in entries:
                    print(f" - {e['path']} (owner: {e['owner']}, mode: {e['mode']}, score: {e['score']})")
        if 'cron_jobs' in self.results:
            print("\n[*] Cron Jobs:")
            for user, jobs in self.results['cron_jobs'].items():
                print(f"\n[+] {user}:")
                for j in jobs:
                    print(f"   {j}")
        if 'launchd_anomalies' in self.results:
            print("\n[*] Launchd Anomalies:")
            for path, entries in self.results['launchd_anomalies'].items():
                print(f"\n[+] {path}:")
                for item in entries:
                    print(f" - {item['file']} (owner: {item['owner']})")
        if 'modules' in self.results:
            print("\n[*] Module Results:")
            for mod, output in self.results['modules'].items():
                print(f"\n[+] {mod}:")
                print(json.dumps(output, indent=2))
        if 'diffs' in self.results:
            print("\n[*] Differences from Last Scan:")
            for k, v in self.results['diffs'].items():
                print(f"\n[!] {k} changed:")
                print(json.dumps(v, indent=2))
        if 'timing' in self.results:
            print("\n[*] Execution Timing (s):")
            for k, v in self.results['timing'].items():
                print(f" - {k}: {v}s")
        print("\n[+] Recon Complete")

    def export(self, fmt="json"):
        fname = f"privdiff_report_{self.timestamp}.{fmt}"
        if fmt == "json":
            with open(fname, "w") as f:
                json.dump(self.results, f, indent=2)
        elif fmt == "txt":
            with open(fname, "w") as f:
                for k, v in self.results.items():
                    f.write(f"== {k.upper()} ==\n")
                    f.write(json.dumps(v, indent=2))
                    f.write("\n\n")
        elif fmt == "csv":
            with open(fname, "w") as f:
                f.write("category,user,path,owner,mode\n")
                for user, items in self.results.get("suid_drifts", {}).items():
                    for i in items:
                        f.write(f"suid,{user},{i['path']},{i['owner']},{i['mode']}\n")
        encoded_trace = base64.b64encode("\n".join([f"{t[0]:.3f}: {t[1]}" for t in list(self.trace_log)]).encode()).decode()
        with open(f"{fname}.trace.b64", "w") as tf:
            tf.write(encoded_trace)

if __name__ == "__main__":
    instance = PrivDiff()
    instance.run_all_checks()
    instance.display_results()
    instance.export("json")
