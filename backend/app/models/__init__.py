"""SQLAlchemy models - importing this package registers every table with Base.metadata."""

from .assets import Asset, AssetChange, Service
from .command import (
    CaseAnnotation,
    CaseFile,
    CaseHypothesis,
    CaseTask,
    CustodyEvent,
    LessonCertificate,
    PostureSnapshot,
    PurpleSimulation,
    SigmaRule,
    UserPreference,
)
from .identity import ApiKey, AuditLog, Project, ProjectMember, Scope, User
from .intel import CveRecord, FindingIntelLink, KevEntry
from .labs import Achievement, Lab, LabRun
from .academy import Lesson, LessonProgress
from .scans import Evidence, Finding, FindingEvent, Job, Scan, ScanEvent
from .soc import Alert, DetectionRule, Incident, IncidentEvent, LogEvent, LogSource
from .system import Report, SettingKV

__all__ = [
    "Achievement",
    "Alert",
    "ApiKey",
    "Asset",
    "AssetChange",
    "CaseAnnotation",
    "CaseFile",
    "CaseHypothesis",
    "CaseTask",
    "CveRecord",
    "CustodyEvent",
    "DetectionRule",
    "Evidence",
    "Finding",
    "FindingEvent",
    "FindingIntelLink",
    "Incident",
    "IncidentEvent",
    "Job",
    "KevEntry",
    "Lab",
    "LabRun",
    "Lesson",
    "LessonCertificate",
    "LessonProgress",
    "LogEvent",
    "LogSource",
    "PostureSnapshot",
    "Project",
    "ProjectMember",
    "PurpleSimulation",
    "Report",
    "Scan",
    "ScanEvent",
    "Scope",
    "Service",
    "SettingKV",
    "SigmaRule",
    "User",
    "UserPreference",
]
