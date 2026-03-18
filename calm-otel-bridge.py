"""
CALM → OTEL → Datadog Agent Bridge
====================================
Coleta telemetria OTLP dos endpoints REST do SAP Cloud ALM, deduplica via
fingerprinting (SQLite) e reexporta via OpenTelemetry SDK para o OTLP
receiver do Datadog Agent.

Requisitos (requirements.txt):
    requests>=2.31
    opentelemetry-api>=1.25
    opentelemetry-sdk>=1.25
    opentelemetry-exporter-otlp-proto-grpc>=1.25
    opentelemetry-exporter-otlp-proto-http>=1.25
    apscheduler>=3.10
    pyyaml>=6.0
    protobuf>=4.25

Fluxo:
    CALM REST (OAuth2) ──► Python (dedup) ──► OTLP/gRPC ──► DD Agent ──► Datadog
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

import requests
import yaml
from apscheduler.schedulers.blocking import BlockingScheduler

# ---------------------------------------------------------------------------
#  OpenTelemetry imports
# ---------------------------------------------------------------------------
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource, SERVICE_NAME
from opentelemetry.sdk._logs import LoggerProvider, LogRecord
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
    OTLPSpanExporter,
)
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
    OTLPMetricExporter,
)
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import (
    OTLPLogExporter,
)
from opentelemetry.trace import StatusCode, Status
from opentelemetry.sdk._logs import LoggingHandler, SeverityNumber
from opentelemetry.semconv.resource import ResourceAttributes

# ---------------------------------------------------------------------------
#  Logging da bridge
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("calm_otel_bridge")

# ---------------------------------------------------------------------------
#  Configuração
# ---------------------------------------------------------------------------
DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"

_EXAMPLE_CONFIG = """\
# config.yaml
calm:
  base_url: "https://<tenant>.alm.cloud.sap"
  token_url: "https://<tenant>.authentication.sap.hana.ondemand.com/oauth/token"
  client_id: ""
  client_secret: ""
  endpoints:
    health_monitoring: "/api/calm-monitoring/v1/health-monitoring"
    real_user_monitoring: "/api/calm-monitoring/v1/real-user-monitoring"
    integration_monitoring: "/api/calm-monitoring/v1/integration-monitoring"
    job_monitoring: "/api/calm-monitoring/v1/job-monitoring"
    synthetic_monitoring: "/api/calm-monitoring/v1/synthetic-monitoring"
  page_size: 100

otel:
  # Endpoint do OTLP receiver no DD Agent
  endpoint: "localhost:4317"
  # Protocolo: grpc ou http
  protocol: "grpc"
  # Compressão: gzip ou none
  compression: "gzip"
  # Timeout em segundos para export
  timeout_seconds: 30

resource:
  service_name: "sap-rise-calm"
  service_namespace: "sap"
  deployment_environment: "production"
  extra_attributes:
    sap.system.type: "S/4HANA"
    sap.rise.tenant: "<tenant-id>"
    cloud.provider: "sap"
    cloud.platform: "sap_btp"

collector:
  interval_seconds: 300
  lookback_minutes: 10
  batch_size: 500
  dedup_ttl_hours: 72

database:
  path: "dedup_state.db"
"""


@dataclass
class CalmConfig:
    base_url: str
    token_url: str
    client_id: str
    client_secret: str
    endpoints: dict[str, str]
    page_size: int = 100


@dataclass
class OtelConfig:
    endpoint: str = "localhost:4317"
    protocol: str = "grpc"
    compression: str = "gzip"
    timeout_seconds: int = 30


@dataclass
class ResourceConfig:
    service_name: str = "sap-rise-calm"
    service_namespace: str = "sap"
    deployment_environment: str = "production"
    extra_attributes: dict[str, str] = field(default_factory=dict)


@dataclass
class CollectorConfig:
    interval_seconds: int = 300
    lookback_minutes: int = 10
    batch_size: int = 500
    dedup_ttl_hours: int = 72


@dataclass
class AppConfig:
    calm: CalmConfig
    otel: OtelConfig
    resource: ResourceConfig
    collector: CollectorConfig
    db_path: str = "dedup_state.db"


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> AppConfig:
    if not path.exists():
        log.error("Config não encontrado: %s", path)
        log.info("Exemplo:\n%s", _EXAMPLE_CONFIG)
        sys.exit(1)

    with open(path) as f:
        raw = yaml.safe_load(f)

    calm_raw = raw.get("calm", {})
    calm_raw["client_id"] = os.getenv("CALM_CLIENT_ID", calm_raw.get("client_id", ""))
    calm_raw["client_secret"] = os.getenv(
        "CALM_CLIENT_SECRET", calm_raw.get("client_secret", "")
    )

    otel_raw = raw.get("otel", {})
    otel_raw["endpoint"] = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", otel_raw.get("endpoint", "localhost:4317"))

    res_raw = raw.get("resource", {})
    coll_raw = raw.get("collector", {})
    db_raw = raw.get("database", {})

    return AppConfig(
        calm=CalmConfig(**calm_raw),
        otel=OtelConfig(**otel_raw),
        resource=ResourceConfig(**res_raw),
        collector=CollectorConfig(**coll_raw),
        db_path=db_raw.get("path", "dedup_state.db"),
    )


# ---------------------------------------------------------------------------
#  Tipos de telemetria
# ---------------------------------------------------------------------------
class TelemetryKind(str, Enum):
    METRIC = "metric"
    LOG = "log"
    TRACE = "trace"


@dataclass
class TelemetryRecord:
    kind: TelemetryKind
    source_endpoint: str
    timestamp: str
    payload: dict[str, Any]
    fingerprint: str = ""

    def compute_fingerprint(self) -> str:
        canonical = json.dumps(
            {
                "kind": self.kind.value,
                "ep": self.source_endpoint,
                "ts": self.timestamp,
                "data": self.payload,
            },
            sort_keys=True,
            default=str,
        )
        self.fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
        return self.fingerprint


# ---------------------------------------------------------------------------
#  Motor de deduplicação (SQLite)
# ---------------------------------------------------------------------------
class DedupEngine:
    def __init__(self, db_path: str, ttl_hours: int = 72):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._ttl_hours = ttl_hours
        self._init_schema()

    def _init_schema(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS fingerprints (
                fp       TEXT PRIMARY KEY,
                kind     TEXT NOT NULL,
                seen_at  TEXT NOT NULL
            )
        """)
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_fp_seen ON fingerprints(seen_at)"
        )
        self._conn.commit()

    def is_duplicate(self, fp: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM fingerprints WHERE fp = ?", (fp,)
        ).fetchone()
        return row is not None

    def register_batch(self, items: list[tuple[str, TelemetryKind]]):
        now = datetime.now(timezone.utc).isoformat()
        self._conn.executemany(
            "INSERT OR IGNORE INTO fingerprints (fp, kind, seen_at) VALUES (?, ?, ?)",
            [(fp, k.value, now) for fp, k in items],
        )
        self._conn.commit()

    def purge_expired(self):
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=self._ttl_hours)
        ).isoformat()
        cur = self._conn.execute(
            "DELETE FROM fingerprints WHERE seen_at < ?", (cutoff,)
        )
        self._conn.commit()
        if cur.rowcount:
            log.info("Dedup: %d fingerprints expirados removidos", cur.rowcount)

    def stats(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT kind, COUNT(*) FROM fingerprints GROUP BY kind"
        ).fetchall()
        return {k: c for k, c in rows}

    def close(self):
        self._conn.close()


# ---------------------------------------------------------------------------
#  Cliente CALM
# ---------------------------------------------------------------------------
class CALMClient:
    def __init__(self, cfg: CalmConfig):
        self._cfg = cfg
        self._session = requests.Session()
        self._token: str | None = None
        self._token_expiry: float = 0.0

    def _ensure_token(self):
        if self._token and time.time() < self._token_expiry - 60:
            return
        log.info("CALM: obtendo token OAuth2…")
        resp = self._session.post(
            self._cfg.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self._cfg.client_id,
                "client_secret": self._cfg.client_secret,
            },
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()
        self._token = body["access_token"]
        self._token_expiry = time.time() + body.get("expires_in", 3600)
        self._session.headers["Authorization"] = f"Bearer {self._token}"

    def _fetch_paginated(
        self, path: str, params: dict[str, Any] | None = None
    ) -> list[dict]:
        self._ensure_token()
        url = f"{self._cfg.base_url.rstrip('/')}{path}"
        params = params or {}
        params.setdefault("$top", self._cfg.page_size)
        params.setdefault("$skip", 0)

        all_results: list[dict] = []
        while True:
            resp = self._session.get(url, params=params, timeout=60)
            if resp.status_code == 401:
                self._token = None
                self._ensure_token()
                resp = self._session.get(url, params=params, timeout=60)
            resp.raise_for_status()

            body = resp.json()
            results = body.get("value", body.get("results", []))
            if isinstance(results, dict):
                results = [results]
            all_results.extend(results)

            if len(results) < self._cfg.page_size:
                break
            if "@odata.nextLink" not in body:
                break
            params["$skip"] += self._cfg.page_size

        return all_results

    def fetch_endpoint(
        self,
        endpoint_key: str,
        kind: TelemetryKind,
        since: datetime,
        until: datetime,
    ) -> list[TelemetryRecord]:
        path = self._cfg.endpoints.get(endpoint_key, "")
        if not path:
            return []

        params = {
            "$filter": (
                f"Timestamp ge datetime'{since.isoformat()}' "
                f"and Timestamp le datetime'{until.isoformat()}'"
            ),
            "$orderby": "Timestamp asc",
        }
        raw = self._fetch_paginated(path, params)
        records = []
        for item in raw:
            ts = item.get("Timestamp") or item.get("timestamp") or since.isoformat()
            r = TelemetryRecord(
                kind=kind,
                source_endpoint=endpoint_key,
                timestamp=ts,
                payload=item,
            )
            r.compute_fingerprint()
            records.append(r)
        log.info("CALM %s: %d registros", endpoint_key, len(records))
        return records


# ---------------------------------------------------------------------------
#  OTEL Exporter — exporta via OpenTelemetry SDK para o DD Agent
# ---------------------------------------------------------------------------
CALM_SEVERITY_MAP = {
    "I": SeverityNumber.INFO,
    "INFO": SeverityNumber.INFO,
    "W": SeverityNumber.WARN,
    "WARNING": SeverityNumber.WARN,
    "WARN": SeverityNumber.WARN,
    "E": SeverityNumber.ERROR,
    "ERROR": SeverityNumber.ERROR,
    "S": SeverityNumber.INFO,
    "SUCCESS": SeverityNumber.INFO,
    "F": SeverityNumber.FATAL,
    "FATAL": SeverityNumber.FATAL,
}


class OTELExporter:
    """Configura providers OTEL e exporta records como spans, métricas e logs."""

    def __init__(self, otel_cfg: OtelConfig, res_cfg: ResourceConfig):
        self._otel_cfg = otel_cfg

        # Resource compartilhado por todos os sinais
        self._resource = Resource.create(
            {
                SERVICE_NAME: res_cfg.service_name,
                ResourceAttributes.SERVICE_NAMESPACE: res_cfg.service_namespace,
                ResourceAttributes.DEPLOYMENT_ENVIRONMENT: res_cfg.deployment_environment,
                **res_cfg.extra_attributes,
            }
        )

        endpoint = otel_cfg.endpoint
        compression_str = otel_cfg.compression
        timeout_ms = otel_cfg.timeout_seconds * 1000

        # --- Trace provider ---
        span_exporter = OTLPSpanExporter(
            endpoint=endpoint,
            insecure=True,
            compression=self._compression_enum(compression_str),
            timeout=timeout_ms,
        )
        self._tracer_provider = TracerProvider(resource=self._resource)
        self._tracer_provider.add_span_processor(
            BatchSpanProcessor(
                span_exporter,
                max_queue_size=2048,
                max_export_batch_size=512,
                schedule_delay_millis=5000,
            )
        )
        trace.set_tracer_provider(self._tracer_provider)
        self._tracer = trace.get_tracer("calm.bridge", "1.0.0")

        # --- Metrics provider ---
        metric_exporter = OTLPMetricExporter(
            endpoint=endpoint,
            insecure=True,
            compression=self._compression_enum(compression_str),
            timeout=timeout_ms,
        )
        reader = PeriodicExportingMetricReader(
            metric_exporter,
            export_interval_millis=10000,
        )
        self._meter_provider = MeterProvider(
            resource=self._resource,
            metric_readers=[reader],
        )
        metrics.set_meter_provider(self._meter_provider)
        self._meter = metrics.get_meter("calm.bridge", "1.0.0")

        # Cache de instrumentos (gauge por nome de métrica)
        self._gauges: dict[str, Any] = {}

        # --- Log provider ---
        log_exporter = OTLPLogExporter(
            endpoint=endpoint,
            insecure=True,
            compression=self._compression_enum(compression_str),
            timeout=timeout_ms,
        )
        self._logger_provider = LoggerProvider(resource=self._resource)
        self._logger_provider.add_log_record_processor(
            BatchLogRecordProcessor(
                log_exporter,
                max_queue_size=2048,
                max_export_batch_size=512,
                schedule_delay_millis=5000,
            )
        )
        self._otel_logger = self._logger_provider.get_logger("calm.bridge", "1.0.0")

    @staticmethod
    def _compression_enum(s: str):
        from grpc import Compression
        return Compression.Gzip if s.lower() == "gzip" else Compression.NoCompression

    # -- Exportar métricas ---------------------------------------------------
    def export_metrics(self, records: list[TelemetryRecord]):
        for r in records:
            metric_name = _sanitize_metric(
                r.payload.get("MetricName")
                or r.payload.get("metricName")
                or f"calm.{r.source_endpoint}"
            )
            fqn = f"sap.calm.{metric_name}"

            value = float(
                r.payload.get("Value")
                or r.payload.get("value")
                or r.payload.get("Rating", 0)
            )

            attrs = {
                "calm.endpoint": r.source_endpoint,
                "calm.fingerprint": r.fingerprint,
                "calm.managed_object": r.payload.get("ManagedObjectId", "unknown"),
                "calm.managed_system": r.payload.get("ManagedSystemId", "unknown"),
            }

            # ObservableGauge com callback — um por nome de métrica
            if fqn not in self._gauges:
                self._gauges[fqn] = {"value": value, "attrs": attrs}
                captured_fqn = fqn

                def make_callback(key):
                    def cb(options):
                        data = self._gauges.get(key)
                        if data:
                            options.observe(data["value"], data["attrs"])
                    return cb

                self._meter.create_observable_gauge(
                    name=fqn,
                    description=f"SAP CALM metric: {metric_name}",
                    callbacks=[make_callback(captured_fqn)],
                    unit="1",
                )
            else:
                self._gauges[fqn] = {"value": value, "attrs": attrs}

        log.info("OTEL metrics: %d registros preparados para export", len(records))

    # -- Exportar logs -------------------------------------------------------
    def export_logs(self, records: list[TelemetryRecord]):
        for r in records:
            ts = self._iso_to_ns(r.timestamp)
            severity_raw = r.payload.get("Severity") or r.payload.get("severity", "I")
            severity = CALM_SEVERITY_MAP.get(severity_raw, SeverityNumber.INFO)

            message = (
                r.payload.get("Message")
                or r.payload.get("message")
                or json.dumps(r.payload, default=str)
            )

            attrs = {
                "calm.endpoint": r.source_endpoint,
                "calm.fingerprint": r.fingerprint,
                "calm.managed_system": r.payload.get("ManagedSystemId", "unknown"),
                "calm.managed_object": r.payload.get("ManagedObjectId", "unknown"),
            }
            # Adiciona campos CALM relevantes como atributos
            for k, v in r.payload.items():
                if isinstance(v, (str, int, float, bool)) and k not in (
                    "Timestamp", "timestamp", "Message", "message"
                ):
                    attrs[f"calm.{_to_snake(k)}"] = str(v)

            self._otel_logger.emit(
                LogRecord(
                    timestamp=ts,
                    severity_number=severity,
                    severity_text=severity_raw,
                    body=message,
                    attributes=attrs,
                )
            )

        log.info("OTEL logs: %d log records emitidos", len(records))

    # -- Exportar traces -----------------------------------------------------
    def export_traces(self, records: list[TelemetryRecord]):
        for r in records:
            op_name = (
                r.payload.get("OperationName")
                or r.payload.get("InterfaceName")
                or f"calm.{r.source_endpoint}"
            )
            duration_ms = int(
                r.payload.get("Duration")
                or r.payload.get("duration")
                or r.payload.get("ResponseTime", 0)
            )

            start_ns = self._iso_to_ns(r.timestamp)
            end_ns = start_ns + (duration_ms * 1_000_000)

            attrs = {
                "calm.endpoint": r.source_endpoint,
                "calm.fingerprint": r.fingerprint,
            }
            for k, v in r.payload.items():
                if isinstance(v, (str, int, float, bool)) and k not in (
                    "Timestamp", "timestamp"
                ):
                    attrs[f"calm.{_to_snake(k)}"] = str(v)

            # Criar span com timestamps explícitos
            span = self._tracer.start_span(
                name=op_name,
                start_time=start_ns,
                attributes=attrs,
            )

            # Mapear status de erro
            status_val = r.payload.get("Status", "")
            if status_val in ("E", "ERROR", "FAILED"):
                span.set_status(
                    Status(StatusCode.ERROR, r.payload.get("ErrorMessage", ""))
                )
                span.set_attribute(
                    "error.message",
                    r.payload.get("ErrorMessage", "CALM reported error"),
                )

            span.end(end_time=end_ns)

        log.info("OTEL traces: %d spans emitidos", len(records))

    # -- Flush explícito (chamado ao final de cada ciclo) --------------------
    def flush(self):
        self._tracer_provider.force_flush(timeout_millis=10000)
        self._meter_provider.force_flush(timeout_millis=10000)
        self._logger_provider.force_flush(timeout_millis=10000)
        log.info("OTEL: flush completo dos 3 sinais")

    def shutdown(self):
        self._tracer_provider.shutdown()
        self._meter_provider.shutdown()
        self._logger_provider.shutdown()

    @staticmethod
    def _iso_to_ns(ts: str) -> int:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            dt = datetime.now(timezone.utc)
        return int(dt.timestamp() * 1e9)


def _sanitize_metric(name: str) -> str:
    return (
        name.lower()
        .replace(" ", "_")
        .replace("-", "_")
        .replace("/", ".")
        .replace("\\", ".")
    )


def _to_snake(name: str) -> str:
    import re
    s = re.sub(r"([A-Z])", r"_\1", name).lower().lstrip("_")
    return s.replace(" ", "_").replace("-", "_")


# ---------------------------------------------------------------------------
#  Orquestrador
# ---------------------------------------------------------------------------
# Mapeamento: endpoint key → tipo de telemetria
ENDPOINT_KIND_MAP: list[tuple[str, TelemetryKind]] = [
    ("health_monitoring", TelemetryKind.METRIC),
    ("synthetic_monitoring", TelemetryKind.METRIC),
    ("real_user_monitoring", TelemetryKind.LOG),
    ("job_monitoring", TelemetryKind.LOG),
    ("integration_monitoring", TelemetryKind.TRACE),
]


class BridgeOrchestrator:
    def __init__(self, cfg: AppConfig):
        self._cfg = cfg
        self._calm = CALMClient(cfg.calm)
        self._exporter = OTELExporter(cfg.otel, cfg.resource)
        self._dedup = DedupEngine(cfg.db_path, cfg.collector.dedup_ttl_hours)

    def run_cycle(self):
        now = datetime.now(timezone.utc)
        since = now - timedelta(minutes=self._cfg.collector.lookback_minutes)
        log.info("=== Ciclo: %s → %s ===", since.isoformat(), now.isoformat())

        # 1) Coleta
        all_records: list[TelemetryRecord] = []
        for ep_key, kind in ENDPOINT_KIND_MAP:
            try:
                records = self._calm.fetch_endpoint(ep_key, kind, since, now)
                all_records.extend(records)
            except requests.RequestException as exc:
                log.error("Erro ao coletar %s: %s", ep_key, exc)
            except Exception as exc:
                log.exception("Erro inesperado em %s: %s", ep_key, exc)

        log.info("Total coletado: %d registros", len(all_records))

        # 2) Deduplicação
        new_records = [r for r in all_records if not self._dedup.is_duplicate(r.fingerprint)]
        dupes = len(all_records) - len(new_records)
        log.info("Após dedup: %d novos, %d duplicados descartados", len(new_records), dupes)

        if not new_records:
            log.info("Nenhum registro novo — ciclo encerrado.")
            return

        # 3) Separar por tipo
        m = [r for r in new_records if r.kind == TelemetryKind.METRIC]
        l = [r for r in new_records if r.kind == TelemetryKind.LOG]
        t = [r for r in new_records if r.kind == TelemetryKind.TRACE]

        # 4) Exportar via OTEL SDK → DD Agent OTLP receiver
        try:
            if m:
                self._exporter.export_metrics(m)
            if l:
                self._exporter.export_logs(l)
            if t:
                self._exporter.export_traces(t)

            # Flush garante que os BatchProcessors enviem tudo agora
            self._exporter.flush()
        except Exception as exc:
            log.error("Erro ao exportar via OTEL: %s", exc)
            return  # Não registra FPs — retry no próximo ciclo

        # 5) Registrar fingerprints enviados
        self._dedup.register_batch([(r.fingerprint, r.kind) for r in new_records])

        # 6) Purge expirados
        self._dedup.purge_expired()

        stats = self._dedup.stats()
        log.info(
            "Ciclo OK — metrics: %d, logs: %d, traces: %d | FPs ativos: %s",
            len(m), len(l), len(t), stats,
        )

    def shutdown(self):
        self._exporter.shutdown()
        self._dedup.close()
        log.info("Bridge encerrada.")


# ---------------------------------------------------------------------------
#  Ponto de entrada
# ---------------------------------------------------------------------------
def main():
    cfg = load_config(Path(os.getenv("BRIDGE_CONFIG", DEFAULT_CONFIG_PATH)))
    orchestrator = BridgeOrchestrator(cfg)

    # Ciclo imediato
    orchestrator.run_cycle()

    # Agendamento periódico
    scheduler = BlockingScheduler()
    scheduler.add_job(
        orchestrator.run_cycle,
        "interval",
        seconds=cfg.collector.interval_seconds,
        id="collection_cycle",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=60,
    )
    log.info("Scheduler: ciclo a cada %ds", cfg.collector.interval_seconds)

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        orchestrator.shutdown()


if __name__ == "__main__":
    main()
