"""
MCP Server Security Auditor
PS02 Hackathon Solution
"""

from dotenv import load_dotenv

load_dotenv(override=True)

__version__ = "1.0.0"
__license__ = "MIT"
__author__ = "Saad Momin, Sawez Farjad, Security Team"
__email__ = "security@brextherfx.site"

from mcpaudit.pipeline import SecurityAuditPipeline, PipelineConfig, PipelineResult

__all__ = [
    "SecurityAuditPipeline",
    "PipelineConfig",
    "PipelineResult",
    "__version__",
]

