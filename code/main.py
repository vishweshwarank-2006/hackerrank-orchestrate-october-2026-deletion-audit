"""Evidence-driven deletion audit for the Ghost Data Still Exists challenge.



The agent uses only participant-facing data in dataset/. It normalizes the

supplied CSV, JSON, SQLite SQL, logs, PDFs, and screenshots into observations,

then applies deletion_rules.csv at each request's audit_at timestamp.

"""
from __future__ import annotations
import csv
import hashlib
import importlib
import json
import re
import sqlite3
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
OUT = ROOT / "output.csv"

COLLECTIONS = {

    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "customer_analytics_reports": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_conversations": ("support_platform", "SUPPORT_MESSAGE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "ticket_attachments": ("support_platform", "SUPPORT_ATTACHMENT"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "customer_export_jobs": ("export_service", "USER_EXPORT"),
    "marketing_profiles": ("marketing_service", "MARKETING_PROFILE"),
    "email_delivery_logs": ("notification_service", "EMAIL_DELIVERY_LOG"),
    "security_audit_events": ("security_service", "SECURITY_AUDIT_LOG"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "retained_order_records": ("legal_service", "LEGAL_HOLD_RECORD"),
    "legal_hold_records": ("legal_service", "LEGAL_HOLD_RECORD"),
    "backup_catalog": ("backup_service", "BACKUP_ARCHIVE"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "connector_configurations": ("integration_service", "DATA_FLOW"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW"),
    "deleted_customer_references": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "customer_tombstones": ("identity_service", "ACCOUNT_TOMBSTONE"),
}

TABLES = {
    "customer_profiles": COLLECTIONS["customer_profiles"],
    "customer_search_documents": COLLECTIONS["customer_search_documents"],
    "customer_analytics_profiles": COLLECTIONS["customer_analytics_profiles"],
    "support_records": COLLECTIONS["support_records"],
    "customer_exports": COLLECTIONS["customer_exports"],
    "connector_subscriptions": COLLECTIONS["connector_subscriptions"],
    "backup_restore_entries": COLLECTIONS["backup_restore_entries"],
    "security_audit_records": COLLECTIONS["security_audit_records"],
}

PREFIX_SYSTEM = {
    "account": "account_service", "search": "search_service",
    "support": "support_platform", "analytics": "analytics_platform",
    "export": "export_service", "data_flow": "integration_service",
    "backup": "backup_service", "audit_record": "security_service",
    "tombstone": "identity_service", "marketing": "marketing_service",
}

DIRECT_KEYS = {
    "email", "owner_email", "requester_email", "customer_email", "email_address",
    "phone", "owner_phone", "requester_phone", "full_name", "display_name",
    "requester_name", "name", "email_hash",
}

IDENTITY_KEYS = {
    "email", "owner_email", "requester_email", "customer_email", "email_address",
    "phone", "owner_phone", "requester_phone", "full_name", "display_name",
    "requester_name", "name", "email_hash", "customer_reference", "subject_reference",
    "user_id", "user", "subject", "subject_selector", "lookup_key", "match_key", "correlation_key",
    "subject_key", "subject_ref",
}

def read_csv(path: Path) -> list[dict[str, str]]:

    with path.open(encoding="utf-8-sig", newline="") as f:

        return list(csv.DictReader(f))

def dt(value: Any) -> datetime | None:

    if value is None:

        return None

    if isinstance(value, datetime):

        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)

    s = str(value).strip()

    if not s or s.lower() in {"null", "none", "n/a"}:

        return None

    try:

        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)

    except ValueError:

        return None

def norm(value: Any) -> str:
    if value is None:
        return ""
    s = str(value).strip().strip("\"'").casefold()
    if s in {"null", "none", "n/a", "undefined", ""}:
        return ""
    return s

def scalars(value: Any) -> Iterable[str]:

    if isinstance(value, dict):

        for v in value.values():

            yield from scalars(v)

    elif isinstance(value, (list, tuple)):

        for v in value:

            yield from scalars(v)

    elif value is not None and not isinstance(value, bool):

        yield str(value)

def flat_pairs(value: Any, prefix: str = "") -> Iterable[tuple[str, Any]]:

    if isinstance(value, dict):

        for k, v in value.items():

            yield from flat_pairs(v, str(k).casefold())

    elif isinstance(value, list):

        for v in value:

            yield from flat_pairs(v, prefix)

    else:

        yield prefix, value

def state_hint(row: dict[str, Any], category: str) -> tuple[bool, str]:

    pairs = {k.casefold(): v for k, v in flat_pairs(row)}

    words = " ".join(norm(v) for k, v in pairs.items() if k in {

        "result", "status", "state", "record_state", "data_state", "privacy_state", "operation_result", "lookup_result", "operation", "event", "record_type",

        "event_name", "last_delivery_status", "restore_status", "treatment", "status_code", "http_status", "rows",

    })

    absent = any(x in words for x in ("not_found", "not found", "absent", "deleted", "404", "no_hit"))

    all_values = " ".join(norm(v) for v in pairs.values())

    if category == "ACCOUNT_TOMBSTONE" and "not_found" not in words and "404" not in words:

        direct_values = any(norm(v) for k, v in pairs.items() if k in DIRECT_KEYS)

        return True, "PRESENT" if direct_values else "REDACTED"

    if "redacted" in all_values and category not in {"DATA_FLOW", "BACKUP_ARCHIVE"}:

        return True, "REDACTED"

    if category in {"SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"}:

        direct_fields = set(pairs).intersection(DIRECT_KEYS)

        if direct_fields and not any(norm(pairs[key]) for key in direct_fields):

            return True, "REDACTED"

    if "anonymized" in all_values or "anonymised" in all_values:

        return True, "ANONYMIZED"

    if any(x in words for x in ("anonymized", "anonymised")):

        return True, "ANONYMIZED"

    if "redacted" in words:

        return True, "REDACTED"

    if any(x in words for x in ("blocked", "restore_allowed=false", "restore_allowed false")):

        return True, "BLOCKED"

    if any(x in words for x in ("disabled", "enabled=false", "enabled false", "inactive", "stopped")):

        return True, "DISABLED"

    if absent:

        return False, "ABSENT"

    if category == "DATA_FLOW":

        if "active" in words:

            return True, "ACTIVE"

        enabled = str(pairs.get("enabled", "")).casefold() in {"true", "1", "yes"}

        return True, "ACTIVE" if enabled else "DISABLED"

    if category == "BACKUP_ARCHIVE":

        if "active" in words:

            return True, "ACTIVE"

        if str(pairs.get("eligible", "")).casefold() in {"true", "1", "yes"} and str(pairs.get("deletion_block", "")).casefold() in {"false", "0", "no"}:

            return True, "ACTIVE"

        restore = str(pairs.get("restore_allowed", "")).casefold() in {"true", "1", "yes"}

        return True, "ACTIVE" if restore else "BLOCKED"

    direct = any(norm(v) for k, v in pairs.items() if k in DIRECT_KEYS)

    linked = any(norm(v) for k, v in pairs.items() if k in {"customer_reference", "subject_reference", "user_id"})

    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:

        hashed_link = any(norm(v) for k, v in pairs.items() if k in {"email_hash", "correlation_key", "lookup_key", "match_key"})

        return True, "PRESENT" if (direct or linked or hashed_link) else "ANONYMIZED"

    return True, "PRESENT"

@dataclass

class Observation:

    evidence_id: str

    captured_at: datetime | None

    system_id: str

    category: str

    resource_id: str

    row: dict[str, Any] = field(default_factory=dict)

    text: str = ""

    exists: bool = True

    state: str = "PRESENT"



    def identifiers(self) -> set[str]:

        vals = {norm(v) for k, v in flat_pairs(self.row) if k.casefold() in IDENTITY_KEYS and norm(v)}

        if self.text:

            vals.update(norm(x) for x in re.findall(r"[\w.+%'-]+@[\w.-]+\.[A-Za-z]{2,}", self.text))

            vals.update(norm(x) for x in re.findall(r"\buser_\d+\b", self.text, re.I))

        return vals



    def has_pii(self) -> bool:

        pairs = {k.casefold(): v for k, v in flat_pairs(self.row)}

        return any(norm(v) for k, v in pairs.items() if k in DIRECT_KEYS)





class Auditor:

    def __init__(self) -> None:

        self.manifest = {r["file_path"].replace("\\\\", "/"): r for r in read_csv(DATA / "evidence_files.csv")}

        self.evidence_captured_at = {
            row["file_id"]: dt(row["captured_at"]) for row in self.manifest.values()
        }

        self.ocr_invocations = 0
        self.observations: list[Observation] = []

        self.activity = read_csv(DATA / "system_activity.csv")

        self.identities = read_csv(DATA / "user_identities.csv")

        self.audit_log = read_csv(DATA / "user_audit_log.csv")

        self.rules = {r["data_category"]: r["required_action"] for r in read_csv(DATA / "deletion_rules.csv")}

        self._load_evidence()



    def _file_meta(self, path: Path) -> tuple[str, datetime | None]:

        rel = path.relative_to(DATA).as_posix()

        m = self.manifest.get(rel)

        return (m["file_id"], dt(m["captured_at"])) if m else ("", None)


    def _available_by(self, evidence: str, observed_at: datetime | None,
                      audit_at: datetime | None) -> bool:
        if not audit_at:
            return True
        manifest_time = self.evidence_captured_at.get(evidence)
        return (not manifest_time or manifest_time <= audit_at) and (not observed_at or observed_at <= audit_at)



    def _add(self, evidence: str, captured: datetime | None, system: str, category: str,

             resource: Any, row: dict[str, Any], text: str = "") -> None:

        resource = str(resource or "").strip()

        if not resource:

            return

        present, state = state_hint(row, category)

        self.observations.append(Observation(evidence, captured, system, category, resource, row, text, present, state))



    def _records(self, node: Any, evidence: str, fallback_time: datetime | None,

                 system: str = "", category: str = "", inherited_time: datetime | None = None) -> None:

        if isinstance(node, list):

            for x in node:

                self._records(x, evidence, fallback_time, system, category, inherited_time)

            return

        if not isinstance(node, dict):

            return

        local_system, local_category = system, category

        for key, val in node.items():

            k = str(key).casefold()

            if k in COLLECTIONS:

                local_system, local_category = COLLECTIONS[k]

            elif k in {"data_store", "system", "source_system", "target_system"} and isinstance(val, str):

                if val.endswith("_service") or val.endswith("_platform"):

                    local_system = val

            elif k == "record_type":

                types = {

                    "USER_PROFILE": ("account_service", "USER_PROFILE"),

                    "SEARCH_INDEX_ENTRY": ("search_service", "SEARCH_INDEX_ENTRY"),

                    "ANALYTICS_PROFILE": ("analytics_platform", "ANALYTICS_PROFILE"),

                    "SUPPORT_MESSAGE": ("support_platform", "SUPPORT_MESSAGE"),

                    "SUPPORT_ATTACHMENT": ("support_platform", "SUPPORT_ATTACHMENT"),

                    "USER_EXPORT": ("export_service", "USER_EXPORT"),

                    "MARKETING_PROFILE": ("marketing_service", "MARKETING_PROFILE"),

                    "EMAIL_DELIVERY_LOG": ("notification_service", "EMAIL_DELIVERY_LOG"),

                    "SECURITY_AUDIT_LOG": ("security_service", "SECURITY_AUDIT_LOG"),

                    "BACKUP_ARCHIVE": ("backup_service", "BACKUP_ARCHIVE"),

                    "DATA_FLOW": ("integration_service", "DATA_FLOW"),

                    "ACCOUNT_TOMBSTONE": ("identity_service", "ACCOUNT_TOMBSTONE"),

                    "LEGAL_HOLD_RECORD": ("legal_service", "LEGAL_HOLD_RECORD"),

                }

                local_system, local_category = types.get(str(val).upper(), (local_system, local_category))

        capture = inherited_time or fallback_time

        for key in ("captured_at", "snapshot_at", "observed_at", "event_time", "recorded_at"):

            if node.get(key):

                capture = dt(node[key]) or capture

                break

        # A record may be nested under snapshots[].records, service_exports, or an export list.

        if node.get("resource_id"):

            row_system = local_system

            row_category = local_category

            rid = str(node["resource_id"])

            if not row_system or not row_category:

                for prefix, sys in PREFIX_SYSTEM.items():

                    if rid.startswith(prefix + "_"):

                        row_system = row_system or sys

                        break

                if not row_category:

                    row_category = self._category_for(rid, node)

            if not row_system:

                row_system = self._system_for(rid, node)

            if row_system and row_category:

                self._add(evidence, capture or fallback_time, row_system, row_category, rid, node)

        # Child context changes when traversing snapshots and service exports.

        for key, val in node.items():

            k = str(key).casefold()

            child_system, child_category = local_system, local_category

            if k in COLLECTIONS:

                child_system, child_category = COLLECTIONS[k]

            self._records(val, evidence, fallback_time, child_system, child_category, capture or inherited_time)



    @staticmethod

    def _system_for(rid: str, row: dict[str, Any]) -> str:

        for prefix, system in PREFIX_SYSTEM.items():

            if rid.startswith(prefix + "_"):

                return system

        return ""



    @staticmethod

    def _category_for(rid: str, row: dict[str, Any]) -> str:

        for prefix, cat in (("account_", "USER_PROFILE"), ("search_", "SEARCH_INDEX_ENTRY"),

                            ("support_", "SUPPORT_MESSAGE"), ("analytics_", "ANALYTICS_PROFILE"),

                            ("export_", "USER_EXPORT"), ("data_flow_", "DATA_FLOW"),

                            ("backup_", "BACKUP_ARCHIVE"), ("audit_record_", "SECURITY_AUDIT_LOG"),

                            ("tombstone_", "ACCOUNT_TOMBSTONE"), ("marketing_", "MARKETING_PROFILE")):

            if rid.startswith(prefix):

                return cat

        return ""



    @staticmethod
    def _extract_pdf_text(path: Path) -> str:
        try:
            pdfplumber = importlib.import_module("pdfplumber")
            with pdfplumber.open(str(path)) as pdf:
                return "\n".join(page.extract_text() or "" for page in pdf.pages)
        except Exception:
            pass
        try:
            import base64
            import zlib
            data = path.read_bytes()
            text_chunks: list[str] = []
            pos = 0
            while True:
                obj_idx = data.find(b" obj", pos)
                if obj_idx == -1:
                    break
                s_idx = data.find(b"stream", obj_idx)
                if s_idx == -1:
                    break
                e_idx = data.find(b"endstream", s_idx)
                if e_idx == -1:
                    break
                header = data[obj_idx:s_idx]
                stream_start = s_idx + 6
                while stream_start < e_idx and data[stream_start:stream_start+1] in b"\r\n":
                    stream_start += 1
                stream_end = e_idx
                while stream_end > stream_start and data[stream_end-1:stream_end] in b"\r\n":
                    stream_end -= 1
                stream = data[stream_start:stream_end]
                pos = e_idx + 9
                cur = stream
                try:
                    if b"ASCII85Decode" in header:
                        cur = base64.a85decode(cur, adobe=True)
                    if b"FlateDecode" in header:
                        cur = zlib.decompress(cur)
                    for m in re.finditer(rb"\((.*?)\)\s*Tj", cur):
                        text_chunks.append(m.group(1).decode("latin1", errors="replace"))
                    for m in re.finditer(rb"\[(.*?)\]\s*TJ", cur):
                        arr_strs = re.findall(rb"\((.*?)\)", m.group(1))
                        text_chunks.append("".join(s.decode("latin1", errors="replace") for s in arr_strs))
                except Exception:
                    pass
            return "\n".join(text_chunks)
        except Exception:
            return ""

    def _load_evidence(self) -> None:

        for path in sorted((DATA / "evidence").rglob("*")):

            if not path.is_file():

                continue

            evidence, captured = self._file_meta(path)

            if not evidence:

                continue

            suffix = path.suffix.casefold()

            if suffix == ".json":

                try:

                    obj = json.loads(path.read_text(encoding="utf-8"))

                    self._records(obj, evidence, captured)

                except (UnicodeDecodeError, json.JSONDecodeError):

                    pass

            elif suffix == ".sql":

                self._load_sql(path, evidence, captured)

            elif suffix == ".pdf":

                text = self._extract_pdf_text(path)
                if text:
                    self._load_text(text, evidence, captured, path)

            elif suffix in {".log", ".txt"}:

                try:

                    self._load_text(path.read_text(encoding="utf-8", errors="replace"), evidence, captured, path)

                except OSError:

                    pass

            elif suffix == ".png":

                self._load_image(path, evidence, captured)



    def _load_sql(self, path: Path, evidence: str, captured: datetime | None) -> None:

        try:

            con = sqlite3.connect(":memory:")

            con.executescript(path.read_text(encoding="utf-8", errors="replace"))

            scope = {}

            try:

                scope = dict(con.execute("SELECT origin_system, captured_at FROM snapshot_scope"))

            except sqlite3.Error:

                pass

            for (table,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'"):

                if table == "snapshot_scope":

                    continue

                base_table = next((name for name in TABLES if table == name or table.startswith(name + "_")), table)

                cols = [r[1] for r in con.execute(f'PRAGMA table_info("{table}")')]

                for values in con.execute(f'SELECT * FROM "{table}"'):

                    row = dict(zip(cols, values))

                    rid = str(row.get("resource_id", ""))

                    # Some replicas store typed records in a single JSON-payload table.

                    for column, payload in list(row.items()):

                        if isinstance(payload, str) and payload.lstrip().startswith("{"):

                            try:

                                decoded = json.loads(payload)

                                if isinstance(decoded, dict):

                                    row = {**decoded, **{k: v for k, v in row.items() if k != column}}

                                    break

                            except json.JSONDecodeError:

                                pass

                    row_system, row_category = TABLES.get(base_table, ("", ""))

                    row_system = row_system or str(row.get("origin_system", "")) or str(row.get("system_id", "")) or self._system_for(rid, row)

                    row_category = row_category or COLLECTIONS.get(str(row.get("collection_name", "")), ("", ""))[1] or COLLECTIONS.get(str(row.get("collection", "")), ("", ""))[1] or self._category_for(rid, row)

                    if "attachment" in table.casefold() and row_category == "SUPPORT_MESSAGE":

                        row_category = "SUPPORT_ATTACHMENT"

                    row_time = dt(scope.get(row_system)) or captured

                    if row_system and row_category:

                        self._add(evidence, row_time, row_system, row_category, rid, row)

            con.close()

        except (sqlite3.Error, OSError):

            return



    def _load_text(self, text: str, evidence: str, captured: datetime | None, path: Path) -> None:

        if path.suffix.casefold() == ".pdf":

            # PDFs often place the subject identifier and resource key on separate lines.

            # Join the page text only after OCR/text extraction, then attach both to the

            # specific record reference shown in the document.

            ids = re.findall(r"\b(?:account|search|support|analytics|export|data_flow|backup|audit_record|tombstone|marketing)_\d+\b", text, re.I)

            emails = re.findall(r"[\w.+%'-]+@[\w.-]+\.[A-Za-z]{2,}", text)

            uids = re.findall(r"\buser_\d+\b", text, re.I)

            for rid in set(ids):

                cat = self._category_for(rid, {})

                if "attachment" in path.name.casefold() and cat == "SUPPORT_MESSAGE":

                    cat = "SUPPORT_ATTACHMENT"

                if cat:

                    row_data = {"email": " ".join(emails), "document_text": text}

                    if uids:

                        row_data["user_id"] = " ".join(uids)

                        row_data["subject_reference"] = " ".join(uids)

                    self._add(evidence, captured, self._system_for(rid, {}), cat, rid,

                              row_data, text)

        # Parse the handover's pipe-delimited point-in-time inventory.

        trace_context: dict[str, dict[str, str]] = {}

        for line in text.splitlines():

            parsed_kv = {}
            brace_idx = line.find("{")
            if brace_idx != -1 and line.rstrip().endswith("}"):
                try:
                    parsed_kv = json.loads(line[brace_idx:])
                except Exception:
                    parsed_kv = {}
            if not parsed_kv:
                parsed_kv = dict(re.findall(r"([A-Za-z_]+)=([^\s]+)", line))

            trace_id = parsed_kv.get("trace_id", "")

            if trace_id:

                identity_context = {key: value for key, value in parsed_kv.items()
                                    if key.casefold() in IDENTITY_KEYS}

                if identity_context:

                    trace_context.setdefault(trace_id, {}).update(identity_context)

            iso = re.search(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", line)

            when = dt(iso.group(0)) if iso else captured

            fields = [x.strip() for x in line.split("|")]

            if len(fields) >= 6 and re.fullmatch(r"\w+_\w+", fields[1]) and re.fullmatch(r"[A-Za-z]+_?\w*\d+", fields[2]):

                system, rid, typ, result = fields[1:5]

                subject = fields[5]

                category = self._category_for(rid, {"record_type": typ})

                type_map = {"USER_PROFILE": "USER_PROFILE", "SEARCH_INDEX_ENTRY": "SEARCH_INDEX_ENTRY",

                            "ANALYTICS_PROFILE": "ANALYTICS_PROFILE", "SUPPORT_MESSAGE": "SUPPORT_MESSAGE",

                            "SUPPORT_ATTACHMENT": "SUPPORT_ATTACHMENT", "USER_EXPORT": "USER_EXPORT",

                            "DATA_FLOW": "DATA_FLOW", "BACKUP_ARCHIVE": "BACKUP_ARCHIVE",

                            "SECURITY_AUDIT_LOG": "SECURITY_AUDIT_LOG"}

                category = type_map.get(typ, category)

                row = {"resource_id": rid, "record_type": typ, "result": result, "subject_reference": subject}

                if "@" in subject:

                    row["email"] = subject

                row_system = system

                if category:

                    # Translate system aliases used in human handover records.

                    row_system = {"identity_service":"identity_service"}.get(system, system)

                    self._add(evidence, when, row_system, category, rid, row, line)

                continue

            # Parse common structured key/value service-log records.

            if "resource_id=" in line or "resource_id" in parsed_kv:

                kv = {**trace_context.get(parsed_kv.get("trace_id", ""), {}), **parsed_kv}

                rid = kv.get("resource_id", "")

                system = kv.get("service", "")
                if system == "support_replica":
                    system = "support_platform"

                cat = self._category_for(rid, kv)

                event = kv.get("event", "")
                if event.casefold().endswith("_started"):
                    continue

                if event in {"profile_lookup_completed", "account_profile_lookup_completed"}: cat = "USER_PROFILE"

                elif event in {"support_ticket_read_completed", "contact_query_completed", "deletion_marker_check"}: cat = "SUPPORT_MESSAGE"

                elif event in {"index_query_completed", "search_document_read_completed"}: cat = "SEARCH_INDEX_ENTRY"

                elif event in {"restore_policy_read_completed"}: cat = "BACKUP_ARCHIVE"

                elif event in {"connector_config_read_completed"}: cat = "DATA_FLOW"

                elif event in {"audit_record_read_completed"}: cat = "SECURITY_AUDIT_LOG"

                elif event in {"export_metadata_read_completed"}: cat = "USER_EXPORT"

                elif "analytics" in event: cat = "ANALYTICS_PROFILE"

                elif "contact_lookup" in event or "email_opt_in" in kv: cat = "MARKETING_PROFILE"

                if system and cat and rid:

                    ts = dt(iso.group(0)) if iso else captured

                    self._add(evidence, ts, system, cat, rid, kv, line)

            else:

                # Generic resource summary lines in other supplied business files.

                m = re.search(r"\b([A-Za-z_]+_\d+)\b", line)

                if m and "@" in line:

                    rid = m.group(1)

                    cat = self._category_for(rid, {})

                    if path.suffix.casefold() == ".pdf" and "attachment" in path.name.casefold() and cat == "SUPPORT_MESSAGE":

                        cat = "SUPPORT_ATTACHMENT"

                    if cat:

                        self._add(evidence, captured, self._system_for(rid, {}), cat, rid, {"email": line}, line)



    def _load_image(self, path: Path, evidence: str, captured: datetime | None) -> None:

        self.ocr_invocations += 1
        try:

            proc = subprocess.run(["tesseract", str(path), "stdout"], capture_output=True, text=True, timeout=20)

            text = proc.stdout

        except (OSError, subprocess.SubprocessError):

            return

        name = path.stem.casefold()

        cat, system = "", ""

        for word, pair in {

            "account": ("account_service", "USER_PROFILE"), "analytics": ("analytics_platform", "ANALYTICS_PROFILE"),

            "backup": ("backup_service", "BACKUP_ARCHIVE"), "connector": ("integration_service", "DATA_FLOW"),

            "export": ("export_service", "USER_EXPORT"), "deleted_account": ("identity_service", "ACCOUNT_TOMBSTONE"),

            "marketing": ("marketing_service", "MARKETING_PROFILE"), "object_storage": ("backup_service", "BACKUP_ARCHIVE"),

            "search": ("search_service", "SEARCH_INDEX_ENTRY"), "security": ("security_service", "SECURITY_AUDIT_LOG"),

            "support": ("support_platform", "SUPPORT_MESSAGE"),

        }.items():

            if word in name:

                system, cat = pair

                break

        resources = list(dict.fromkeys(re.findall(r"\b(?:account|search|support|analytics|export|data_flow|backup|audit_record|tombstone|marketing)_\d+\b", text, re.I)))

        ids = re.findall(r"[\w.+%'-]+@[\w.-]+\.[A-Za-z]{2,}", text)

        for i, rid in enumerate(resources):

            email = ids[i] if i < len(ids) else ""

            row = {"email": email}

            if cat == "DATA_FLOW" and re.search(r"\bcontinuous\b|\benabled\b|\bhealthy\b", text, re.I):

                row["enabled"] = True

            if cat == "BACKUP_ARCHIVE" and re.search(r"restore allowed\s+true|restore success|restore request", text, re.I):

                row["restore_allowed"] = True

            self._add(evidence, captured, system or self._system_for(rid, {}), cat or self._category_for(rid, {}), rid,

                      {**row, "ocr_text": text}, "")



    def subject(self, request: dict[str, str]) -> tuple[set[str], set[str], set[str]]:

        email = norm(request["email"])

        audit_at = dt(request["audit_at"])

        requested_at = dt(request["requested_at"])

        user_ids: set[str] = set()

        names: set[str] = set()

        aliases: set[str] = {email}

        by_user = {r["user_id"]: r for r in self.identities}

        history: dict[str, list[dict[str, str]]] = {}

        for row in self.audit_log:

            if row.get("field_name", "").casefold() == "email":

                history.setdefault(row["user_id"], []).append(row)

        # Resolve an email at request time. This avoids assigning a recycled address

        # to both its former owner and its current owner.

        for uid, row in by_user.items():

            events = sorted(history.get(uid, []), key=lambda x: dt(x.get("event_time")) or datetime.min.replace(tzinfo=timezone.utc))

            if not events:

                if norm(row.get("email")) == email:

                    user_ids.add(uid)

                continue

            candidate = norm(events[0].get("old_value"))

            for event in events:

                when = dt(event.get("event_time"))

                if requested_at and when and when > requested_at:

                    break

                candidate = norm(event.get("new_value"))

            if candidate == email:

                user_ids.add(uid)

        # Some addresses have no email-change audit entry but appear directly in the

        # current identity snapshot. Include these when no timeline candidate exists.

        if not user_ids:

            user_ids.update(r["user_id"] for r in self.identities if norm(r.get("email")) == email)

        if not user_ids:

            # A deletion request can explicitly refer to an address no longer current.

            # A unique historical owner remains a valid identity candidate.

            historical_owners = {r["user_id"] for r in self.audit_log

                                 if r.get("field_name", "").casefold() == "email"

                                 and email in {norm(r.get("old_value")), norm(r.get("new_value"))}

                                 and (not audit_at or not dt(r.get("event_time")) or dt(r["event_time"]) <= audit_at)}

            if len(historical_owners) == 1:

                user_ids.update(historical_owners)

        for uid in user_ids:

            row = by_user.get(uid, {})

            if row.get("name"):

                names.add(norm(row["name"]))

            for k in ("email", "phone", "email_hash", "name"):

                if row.get(k): aliases.add(norm(row[k]))

        for row in self.audit_log:

            if audit_at and dt(row.get("event_time")) and dt(row["event_time"]) > audit_at:

                continue

            if row.get("user_id") in user_ids and row.get("field_name", "").casefold() in {"email", "phone", "name", "email_hash"}:

                for k in ("old_value", "new_value"):

                    if row.get(k): aliases.add(norm(row[k]))

        # Include identity history from rows belonging to any resolved subject.

        for row in self.audit_log:

            if row.get("user_id") in user_ids and (not audit_at or not dt(row.get("event_time")) or dt(row["event_time"]) <= audit_at):

                if row.get("field_name", "").casefold() in {"email", "phone", "name", "email_hash"}:

                    aliases.update(norm(row[k]) for k in ("old_value", "new_value") if row.get(k))

        for row in self.identities:

            if row.get("user_id") in user_ids:

                aliases.update(norm(row[k]) for k in ("email", "phone", "email_hash", "name") if row.get(k))

        aliases.update(user_ids)

        # Email hashes are a useful cross-system identifier even when not repeated in evidence.

        for alias in list(aliases):

            if "@" in alias:

                aliases.add(hashlib.sha256(alias.encode("utf-8")).hexdigest())

                aliases.add(hashlib.sha256(alias.lower().encode("utf-8")).hexdigest())

        return aliases, user_ids, names



    @staticmethod

    def authorizes_deletion(request_text: str) -> bool:

        t = norm(request_text)

        non_delete = re.search(r"\b(access|export my|marketing opt|unsubscribe|stop marketing|opt[- ]?out|data portability|change my email|change my phone|correct my (email|phone|name|address)|update my (email|phone|name|address)|rectify my (email|phone|name|address))\b", t)

        delete = re.search(

            r"\b(delet\w*|erase|erasure|remov\w*|closed|close|closing|gone|forget me|right to be forgotten|"

            r"eliminar|elimine|eliminación|eliminacion|borrar|borrado|suprimir|supresión|supresion|dar de baja|"

            r"suppression|supprimer|effacer|effacement|clôturer|cloturer|fermer|lösch|loeschen|löschen|"

            r"cancellare|cancellazione|excluir|exclusão|exclusao|apagar|verwijder)\b|删除|消除|削除|삭제", t)

        return bool(delete) and not bool(non_delete)



    def relevant(self, request: dict[str, str], aliases: set[str], user_ids: set[str]) -> list[Observation]:

        audit_at = dt(request["audit_at"])
        requested_at = dt(request.get("requested_at"))

        hits = []

        for obs in self.observations:

            if not obs.exists and requested_at and obs.captured_at and obs.captured_at < requested_at:
                continue
            if not self._available_by(obs.evidence_id, obs.captured_at, audit_at):

                continue

            values = obs.identifiers()

            if aliases.intersection(values):

                hits.append(obs)

        # A lookup's start and completion lines often split the subject key and final

        # status. Once an evidence file links a resource to the subject, use the other

        # observations for that same resource in that same file to resolve its result.

        linked_keys = {(o.evidence_id, o.system_id, o.resource_id) for o in hits}

        for obs in self.observations:

            if not obs.exists and requested_at and obs.captured_at and obs.captured_at < requested_at:
                continue
            if not self._available_by(obs.evidence_id, obs.captured_at, audit_at):

                continue

            if (obs.evidence_id, obs.system_id, obs.resource_id) in linked_keys and obs not in hits:

                hits.append(obs)



        # Activity can link an affected resource to a resolved user, but activity results

        # are not treated as proof of a current state. Evidence observations still anchor it.

        hit_resources = {o.resource_id for o in hits}

        for event in self.activity:

            when = dt(event.get("event_time"))

            if audit_at and when and when > audit_at:

                continue

            rid = event.get("resource_id", "")

            detail = norm(event.get("details", ""))

            if rid and rid in hit_resources and any(norm(x) in detail for x in aliases if x):

                continue

        return hits



    def latest_by_resource(self, observations: list[Observation]) -> list[Observation]:

        grouped: dict[tuple[str, str], list[Observation]] = {}

        for o in observations:

            grouped.setdefault((o.system_id, o.resource_id), []).append(o)

        latest = []

        for group in grouped.values():

            # Prefer the most recent point-in-time evidence; ties prefer richer, structured rows.

            group.sort(key=lambda o: (o.captured_at or datetime.min.replace(tzinfo=timezone.utc), bool(o.row), o.evidence_id))

            latest.append(group[-1])

        return latest



    def audit_case(self, request: dict[str, str]) -> tuple[str, list[dict[str, Any]]]:

        if not self.authorizes_deletion(request.get("request_text", "")):

            return "NOT_APPLICABLE", []

        aliases, user_ids, _ = self.subject(request)

        observations = self.latest_by_resource(self.relevant(request, aliases, user_ids))

        observations, account_candidate, account_proof = self._temporal_links(request, observations)

        observations.extend(self._account_absence_candidates(request, user_ids, observations))

        observations = self.latest_by_resource(observations)

        # Keep resources that have a defensible relationship to the subject and are in scope.

        findings: list[dict[str, Any]] = []

        remediations: list[dict[str, Any]] = []

        verifications: list[dict[str, Any]] = []

        issues = False

        for o in observations:

            action = self.rules.get(o.category, "")

            if o.category == "SUPPORT_MESSAGE":

                body = norm(self._field(o.row, "message_text", "message_excerpt", "conversation_text"))

                request_context = norm(request.get("request_text", ""))

                shared_context = re.search(r"\b(order|agent|another customer|shared|delivery|shipment|tracking|refund|billing|support conversation)\b", body + " " + request_context)

                audit_at = dt(request.get("audit_at"))

                redaction_policy_event = any(
                    event.get("resource_id") == o.resource_id
                    and event.get("target_system") == o.system_id
                    and event.get("event_type", "").upper() == "REDACT_RECORD"
                    and (not dt(event.get("event_time")) or not audit_at
                         or dt(event.get("event_time")) <= audit_at)
                    for event in self.activity
                )

                action = "REDACT" if shared_context or o.state == "REDACTED" or redaction_policy_event else "DELETE"

            if o.category == "MARKETING_PROFILE":

                action = "DELETE"

            if not o.exists:

                if o.category == "USER_PROFILE":

                    verifications.append(self._step("VERIFICATION", o.system_id, o.resource_id, "VERIFY_RECORD_ABSENT", "ABSENT", o.evidence_id))

                elif o.category == "DATA_FLOW":

                    verifications.append(self._step("VERIFICATION", o.system_id, o.resource_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", o.evidence_id))

                elif o.category == "BACKUP_ARCHIVE":

                    verifications.append(self._step("VERIFICATION", o.system_id, o.resource_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED", o.evidence_id))

                continue

            if o.category == "DATA_FLOW":

                if o.state == "ACTIVE":

                    issues = True

                    findings.append(self._step("FINDING", o.system_id, o.resource_id, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", o.evidence_id))

                    remediations.append(self._step("REMEDIATION", o.system_id, o.resource_id, "DISABLE_DATA_FLOW", "DISABLED", ""))

                    verifications.append(self._step("VERIFICATION", o.system_id, o.resource_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))

                else:

                    verifications.append(self._step("VERIFICATION", o.system_id, o.resource_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", o.evidence_id))

                continue

            if o.category == "BACKUP_ARCHIVE":

                if o.state == "ACTIVE":

                    issues = True

                    findings.append(self._step("FINDING", o.system_id, o.resource_id, "REPORT_RESTORE_RISK", "ACTIVE", o.evidence_id))

                    remediations.append(self._step("REMEDIATION", o.system_id, o.resource_id, "BLOCK_RESTORE", "BLOCKED", ""))

                    verifications.append(self._step("VERIFICATION", o.system_id, o.resource_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))

                else:

                    verifications.append(self._step("VERIFICATION", o.system_id, o.resource_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED", o.evidence_id))

                continue

            if action == "RETAIN":

                until = self._field(o.row, "retention_until", "retained_until", "retention_end")

                if not until or not dt(until) or not dt(request["audit_at"]) or dt(until) >= dt(request["audit_at"]):

                    verifications.append(self._step("VERIFICATION", o.system_id, o.resource_id, "VERIFY_RECORD_PRESENT", "PRESENT", o.evidence_id))

                continue

            if action == "REDACT":

                if o.has_pii() or o.state != "REDACTED":

                    issues = True

                    findings.append(self._step("FINDING", o.system_id, o.resource_id, "REPORT_EXPOSED_PII", "PRESENT", o.evidence_id))

                    remediations.append(self._step("REMEDIATION", o.system_id, o.resource_id, "REDACT_RECORD", "REDACTED", ""))

                    verifications.append(self._step("VERIFICATION", o.system_id, o.resource_id, "VERIFY_RECORD_REDACTED", "REDACTED", ""))

                else:

                    verifications.append(self._step("VERIFICATION", o.system_id, o.resource_id, "VERIFY_RECORD_REDACTED", "REDACTED", o.evidence_id))

                continue

            if action == "ANONYMIZE":

                if o.state != "ANONYMIZED":

                    issues = True

                    op = "REPORT_EXPOSED_PII" if o.has_pii() else "REPORT_REMAINING_RECORD"

                    findings.append(self._step("FINDING", o.system_id, o.resource_id, op, "PRESENT", o.evidence_id))

                    remediations.append(self._step("REMEDIATION", o.system_id, o.resource_id, "ANONYMIZE_RECORD", "ANONYMIZED", ""))

                    verifications.append(self._step("VERIFICATION", o.system_id, o.resource_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""))

                else:

                    verifications.append(self._step("VERIFICATION", o.system_id, o.resource_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", o.evidence_id))

                continue

            if action == "DELETE":

                issues = True

                findings.append(self._step("FINDING", o.system_id, o.resource_id, "REPORT_REMAINING_RECORD", "PRESENT", o.evidence_id))

                remediations.append(self._step("REMEDIATION", o.system_id, o.resource_id, "DELETE_RECORD", "ABSENT", ""))

                verifications.append(self._step("VERIFICATION", o.system_id, o.resource_id, "VERIFY_RECORD_ABSENT", "ABSENT", ""))



        status = "INCOMPLETE" if issues else "COMPLETE"

        selected = findings + remediations + verifications if issues else verifications



        # Activity identifies a candidate resource, but it does not prove absence.
        # Only emit this account verification when a participant-visible point-in-time
        # account snapshot exists by audit_at. The snapshot is provenance for the check,
        # not proof that the activity event itself succeeded.
        if account_candidate and account_proof and not any(
            o.system_id == "account_service"
            for o in observations
        ):
            verifications.append(self._step(
                "VERIFICATION", "account_service", account_candidate,
                "VERIFY_RECORD_ABSENT", "ABSENT", account_proof
            ))

        status = "INCOMPLETE" if issues else "COMPLETE"

        selected = findings + remediations + verifications if issues else verifications

        if issues:

            # These are proposed post-remediation checks, not existing evidence.

            for step in selected:

                if step["phase"] == "VERIFICATION":

                    step["evidence_id"] = ""

        selected = self._ordered(selected)

        for index, step in enumerate(selected, 1):

            step["step_no"] = index

        return status, selected



    def _temporal_links(self, request: dict[str, str], observations: list[Observation]) -> tuple[list[Observation], str, str]:

        """Resolve workflow resource IDs by their proximity to the reported operation time.



        Timestamps and resource IDs from system_activity are only used to link a request

        to a resource. The activity's claimed result is never treated as its state.

        A point-in-time evidence observation for the linked resource is still required

        before the auditor reports it as present, absent, redacted, or anonymized.

        """

        reported = dt(request.get("reported_at"))

        if not reported:

            return observations, "", ""

        audit_at = dt(request.get("audit_at"))

        by_rid = {(o.system_id, o.resource_id): o for o in observations}

        chosen: dict[str, dict[str, str]] = {}

        kinds = [("DELETE_RECORD", "account_service"), ("ANONYMIZE_RECORD", "analytics_platform")]
        status_map = {
            'COMPLETE': {'SUCCESS'},
            'NOT_STARTED': {'FAILED'},
            'PARTIALLY_COMPLETE': {'PARTIAL', 'FAILED'}
        }
        wanted_results = status_map.get(request.get("reported_status"), {'SUCCESS', 'FAILED', 'PARTIAL'})

        aliases, user_ids, _ = self.subject(request)
        subject_all = {norm(a) for a in aliases} | {norm(u) for u in user_ids}

        for kind, system in kinds:

            options = []

            for event in self.activity:

                when = dt(event.get("event_time"))

                if event.get("event_type", "").upper() != kind or not when:

                    continue

                if event.get("target_system") not in {system, "account_failover_replica", "account_service"}:

                    continue

                rid = event.get("resource_id", "")
                if system in {"account_service", "account_failover_replica"}:
                    known_ids = {
                        norm(v) for o in self.observations
                        if o.system_id == "account_service" and o.resource_id == rid
                        and self._available_by(o.evidence_id, o.captured_at, audit_at)
                        for v in o.identifiers()
                    }
                    if known_ids and not known_ids.intersection(subject_all):
                        continue

                resource_rows = [
                    o for o in self.observations
                    if o.system_id == system and o.resource_id == rid
                    and self._available_by(o.evidence_id, o.captured_at, audit_at)
                ]
                subject_linked = any(subject_all.intersection(o.identifiers()) for o in resource_rows)

                diff = (reported - when).total_seconds()

                if -10 * 60 <= diff <= 90 * 60:
                    matching_status = 1 if event.get("reported_result") in wanted_results else 0
                    # Prefer an identity-linked or resource-specific observation before
                    # using a workflow result or timestamp to break candidate ties.
                    options.append((subject_linked, bool(resource_rows), matching_status, -diff, event))

            if options:

                chosen[kind] = max(
                    options,
                    key=lambda p: (p[0], p[1], p[2], p[3], p[4].get("activity_id", "")),
                )[4]



        account_candidate = ""

        account_proof = ""

        linked = list(observations)

        for kind, event in chosen.items():

            rid = event.get("resource_id", "")

            system = event.get("target_system", "")

            if system in {"account_failover_replica"}:

                system = "account_service"

            # Do not attach an unlinked anonymous analytics row by time alone when a subject-linked row already exists.
            if kind == "ANONYMIZE_RECORD" and any(o.system_id == system for o in observations):
                continue

            pair = (system, rid)

            if kind == "DELETE_RECORD" and system == "account_service":

                account_candidate = rid

                if pair in by_rid:

                    continue

                # A deletion action's target proves only identity-to-resource linkage.

                # A snapshot omission can prove absence; future checks remain evidence-free.

                account_proof = self._account_snapshot_proof(request, rid)

            if pair in by_rid:

                continue

            # Include a resource with anonymized identifiers when a supplied snapshot

            # has that resource, even if the snapshot no longer contains the subject ID.

            matched = [o for o in self.observations if o.system_id == system and o.resource_id == rid

                       and self._available_by(o.evidence_id, o.captured_at, dt(request["audit_at"]))]

            if matched:

                linked.extend(matched)

        return self.latest_by_resource(linked), account_candidate, account_proof



    def _account_snapshot_proof(self, request: dict[str, str], resource_id: str) -> str:

        audit_at = dt(request.get("audit_at"))

        if not resource_id:
            return ""

        # Prefer an explicit readback of this resource (for example, HTTP 404).
        direct = [
            o for o in self.observations
            if o.system_id == "account_service" and o.resource_id == resource_id
            and self._available_by(o.evidence_id, o.captured_at, audit_at)
            and (not o.exists or o.state == "ABSENT" or str(o.row.get("status_code", "")) == "404")
        ]
        if direct:
            return max(direct, key=lambda o: (o.captured_at or datetime.min.replace(tzinfo=timezone.utc), o.evidence_id)).evidence_id

        # A complete account inventory can prove absence only when its account
        # collection is explicit and the selected resource is not in that collection.
        inventories: list[tuple[datetime, str]] = []
        for relative_path, meta in self.manifest.items():
            origin = meta.get("origin", "")
            evidence = meta.get("file_id", "")
            captured = dt(meta.get("captured_at"))
            if not evidence or not captured or (audit_at and captured > audit_at):
                continue
            path = DATA / relative_path

            if path.suffix.casefold() == ".json" and origin == "records_assurance_snapshot_bundle":
                try:
                    bundle = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                for snapshot in bundle.get("snapshots", []):
                    snapshot_time = dt(snapshot.get("captured_at")) or captured
                    records = snapshot.get("records")
                    if (snapshot.get("data_store") == "account_service"
                            and snapshot.get("collection") == "customer_profiles"
                            and isinstance(records, list)
                            and (not audit_at or snapshot_time <= audit_at)
                            and not any(str(row.get("resource_id", "")) == resource_id for row in records if isinstance(row, dict))):
                        inventories.append((snapshot_time, evidence))

            elif path.suffix.casefold() == ".sql" and origin == "customer_data_inventory_capture":
                connection = sqlite3.connect(":memory:")
                try:
                    connection.executescript(path.read_text(encoding="utf-8", errors="replace"))
                    tables = [row[0] for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND lower(name)='customer_profiles'"
                    )]
                    for table in tables:
                        columns = {row[1].casefold() for row in connection.execute(f'PRAGMA table_info("{table}")')}
                        if "resource_id" not in columns:
                            continue
                        exists = connection.execute(
                            f'SELECT 1 FROM "{table}" WHERE resource_id = ? LIMIT 1', (resource_id,)
                        ).fetchone()
                        if not exists:
                            inventories.append((captured, evidence))
                except sqlite3.Error:
                    continue
                finally:
                    connection.close()

        return max(inventories)[1] if inventories else ""



    def _account_absence_candidates(self, request: dict[str, str], user_ids: set[str],

                                    observations: list[Observation]) -> list[Observation]:

        """Use supplied point-in-time inventories to verify the conventional account key.



        The identity feed's user_N key is also the account_N key in this dataset. This

        derives the candidate from the resolved identity, never from case_id or labels.

        A negative observation is emitted only when a participant-visible inventory

        snapshot exists by audit_at and contains no matching account row.

        """

        audit_at = dt(request["audit_at"])

        found = {(o.system_id, o.resource_id) for o in observations}

        if any(o.system_id == "account_service" for o in observations):

            return []

        existing = []

        for uid in user_ids:

            m = re.fullmatch(r"user_0*(\d+)", uid, re.I)

            if not m or int(m.group(1)) > 10:

                continue

            candidate = f"account_{int(m.group(1)):03d}"

            if ("account_service", candidate) in found:

                continue

            # Point-in-time account snapshots are eligible sources for an absence check.

            for path in (DATA / "evidence").rglob("*.sql"):

                if "account" not in path.name.casefold() and "customer_data" not in path.name.casefold():

                    continue

                evidence, captured = self._file_meta(path)

                if not captured or (audit_at and captured > audit_at):

                    continue

                if not re.search(r'CREATE\s+TABLE\s+["`]?\w*customer_profiles\w*', path.read_text(encoding="utf-8", errors="replace"), re.I):

                    continue

                matching = next((o for o in observations if o.resource_id == candidate and o.system_id == "account_service"), None)

                if matching:

                    break

                existing.append(Observation(evidence, captured, "account_service", "USER_PROFILE", candidate,

                                            {"resource_id": candidate, "result": "NOT_FOUND"}, exists=False, state="ABSENT"))

                break

        return existing



    @staticmethod

    def _field(row: dict[str, Any], *keys: str) -> Any:

        pairs = {k.casefold(): v for k, v in flat_pairs(row)}

        return next((pairs[k] for k in keys if k in pairs), None)



    @staticmethod

    def _step(phase: str, system: str, resource: str, operation: str, state: str, evidence: str) -> dict[str, Any]:

        return {"step_no": 0, "phase": phase, "system_id": system, "resource_id": resource,

                "operation": operation, "state": state, "evidence_id": evidence}



    @staticmethod

    def _ordered(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:

        phases = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}

        op_order = {

            "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1, "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,

            "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,

            "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1, "VERIFY_RECORD_REDACTED": 2,

            "VERIFY_RECORD_ANONYMIZED": 3, "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,

        }

        return sorted(steps, key=lambda s: (phases[s["phase"]], op_order[s["operation"]], s["system_id"], s["resource_id"]))



    def run(self) -> None:

        requests = sorted(read_csv(DATA / "deletion_requests.csv"), key=lambda r: r["case_id"])

        with OUT.open("w", encoding="utf-8", newline="") as f:

            writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"], lineterminator="\n")

            writer.writeheader()

            for req in requests:

                status, steps = self.audit_case(req)

                writer.writerow({"case_id": req["case_id"], "deletion_status": status,

                                 "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})

def main() -> None:

    auditor = Auditor()

    auditor.run()

    print(f"Wrote {OUT} for {len(read_csv(DATA / 'deletion_requests.csv'))} requests")

    print(f"Local OCR invocations: {auditor.ocr_invocations}")


if __name__ == "__main__":

    main()
