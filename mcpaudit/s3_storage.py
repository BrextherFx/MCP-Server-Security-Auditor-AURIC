import os
import shutil
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    boto3 = None
    ClientError = Exception
    NoCredentialsError = Exception
    HAS_BOTO3 = False

from dotenv import load_dotenv

load_dotenv(override=True)


class S3StorageManager:
    """Manages SQLite database backups and security report archives to AWS S3 bucket

    (with local simulated bucket directory fallback for testing without credentials).
    """

    def __init__(
        self,
        bucket_name: Optional[str] = None,
        region_name: Optional[str] = None,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        local_mock_dir: str = "s3_bucket_storage",
    ):
        load_dotenv(override=True)
        self.bucket_name = (
            bucket_name
            or os.environ.get("AWS_S3_BUCKET")
            or "mcp-security-auditor-bucket"
        )
        self.region_name = (
            region_name
            or os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
            or "us-east-1"
        )
        raw_key = aws_access_key_id or os.environ.get("AWS_ACCESS_KEY_ID")
        raw_secret = aws_secret_access_key or os.environ.get("AWS_SECRET_ACCESS_KEY")

        # Ignore placeholder values
        if raw_key and any(ph in raw_key.lower() for ph in ["your_access_key", "your_aws", "placeholder", "xxx"]):
            raw_key = None
        if raw_secret and any(ph in raw_secret.lower() for ph in ["your_secret", "your_aws", "placeholder", "xxx"]):
            raw_secret = None

        self.access_key = raw_key
        self.secret_key = raw_secret
        self.endpoint_url = endpoint_url or os.environ.get("AWS_S3_ENDPOINT_URL")
        self.local_mock_dir = Path(local_mock_dir)
        self._s3_client = None
        self._is_live_aws = False
        self._init_client()

    def _init_client(self):
        """Initializes boto3 client if credentials or default profile exist."""
        if not HAS_BOTO3 or boto3 is None:
            self._s3_client = None
            self._is_live_aws = False
            return

        try:
            kwargs: Dict[str, Any] = {"region_name": self.region_name}
            if self.access_key and self.secret_key:
                kwargs["aws_access_key_id"] = self.access_key
                kwargs["aws_secret_access_key"] = self.secret_key
            if self.endpoint_url:
                kwargs["endpoint_url"] = self.endpoint_url

            client = boto3.client("s3", **kwargs)
            if self.access_key:
                self._s3_client = client
                self._is_live_aws = True
            else:
                # Check if default environment/instance profile credentials exist
                try:
                    client.head_bucket(Bucket=self.bucket_name)
                    self._s3_client = client
                    self._is_live_aws = True
                except Exception:
                    self._s3_client = None
                    self._is_live_aws = False
        except Exception:
            self._s3_client = None
            self._is_live_aws = False

    def get_status(self) -> Dict[str, Any]:
        """Returns connection status, active bucket name, and storage mode."""
        return {
            "bucket_name": self.bucket_name,
            "region": self.region_name,
            "mode": "AWS S3 Cloud" if self._is_live_aws else "Local S3 Bucket Simulation",
            "is_live_aws": self._is_live_aws,
            "storage_path": f"s3://{self.bucket_name}/" if self._is_live_aws else str(self.local_mock_dir / self.bucket_name),
        }

    def sync_database_to_s3(
        self,
        local_db_path: str = "mcpaudit_pins.db",
        s3_key: str = "databases/mcpaudit_pins.db",
    ) -> Dict[str, Any]:
        """Uploads the local SQLite database to the S3 bucket."""
        path = Path(local_db_path)
        if not path.exists():
            return {"success": False, "error": f"Database file '{local_db_path}' not found."}

        timestamp = datetime.now(timezone.utc).isoformat()
        if self._is_live_aws and self._s3_client:
            try:
                self._s3_client.upload_file(str(path), self.bucket_name, s3_key)
                s3_uri = f"s3://{self.bucket_name}/{s3_key}"
                return {
                    "success": True,
                    "s3_uri": s3_uri,
                    "synced_at": timestamp,
                    "mode": "AWS S3",
                    "file_size": path.stat().st_size,
                }
            except Exception as e:
                return {"success": False, "error": str(e)}

        # Local simulated S3 bucket storage fallback
        mock_target = self.local_mock_dir / self.bucket_name / s3_key
        mock_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(path), str(mock_target))
        return {
            "success": True,
            "s3_uri": f"s3://{self.bucket_name}/{s3_key}",
            "local_path": str(mock_target),
            "synced_at": timestamp,
            "mode": "Local S3 Simulation",
            "file_size": path.stat().st_size,
        }

    def restore_database_from_s3(
        self,
        s3_key: str = "databases/mcpaudit_pins.db",
        local_db_path: str = "mcpaudit_pins.db",
    ) -> Dict[str, Any]:
        """Pulls the SQLite database from the S3 bucket to restore local state."""
        if self._is_live_aws and self._s3_client:
            try:
                self._s3_client.download_file(self.bucket_name, s3_key, local_db_path)
                return {
                    "success": True,
                    "message": f"Restored {local_db_path} from s3://{self.bucket_name}/{s3_key}",
                }
            except Exception as e:
                return {"success": False, "error": str(e)}

        mock_source = self.local_mock_dir / self.bucket_name / s3_key
        if not mock_source.exists():
            return {
                "success": False,
                "error": f"S3 object '{s3_key}' not found in bucket '{self.bucket_name}'.",
            }

        shutil.copyfile(str(mock_source), local_db_path)
        return {
            "success": True,
            "message": f"Restored {local_db_path} from simulated S3 ({mock_source})",
        }

    def upload_report_to_s3(
        self,
        content: str,
        filename: str,
        server_id: str,
        content_type: str = "text/plain",
    ) -> Dict[str, Any]:
        """Uploads a generated report (Markdown, SARIF, JSON, HTML) directly to S3."""
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        s3_key = f"reports/{server_id}/{date_str}_{filename}"
        timestamp = datetime.now(timezone.utc).isoformat()

        if self._is_live_aws and self._s3_client:
            try:
                self._s3_client.put_object(
                    Bucket=self.bucket_name,
                    Key=s3_key,
                    Body=content.encode("utf-8"),
                    ContentType=content_type,
                )
                return {
                    "success": True,
                    "s3_uri": f"s3://{self.bucket_name}/{s3_key}",
                    "s3_key": s3_key,
                    "uploaded_at": timestamp,
                    "mode": "AWS S3",
                }
            except Exception as e:
                return {"success": False, "error": str(e)}

        # Local S3 simulation
        mock_file = self.local_mock_dir / self.bucket_name / s3_key
        mock_file.parent.mkdir(parents=True, exist_ok=True)
        mock_file.write_text(content, encoding="utf-8")
        return {
            "success": True,
            "s3_uri": f"s3://{self.bucket_name}/{s3_key}",
            "s3_key": s3_key,
            "local_path": str(mock_file),
            "uploaded_at": timestamp,
            "mode": "Local S3 Simulation",
        }

    def list_archived_reports(self) -> List[Dict[str, Any]]:
        """Lists all reports archived in the S3 bucket."""
        reports: List[Dict[str, Any]] = []

        if self._is_live_aws and self._s3_client:
            try:
                res = self._s3_client.list_objects_v2(
                    Bucket=self.bucket_name,
                    Prefix="reports/",
                )
                for obj in res.get("Contents", []):
                    reports.append({
                        "key": obj["Key"],
                        "size": obj["Size"],
                        "last_modified": obj["LastModified"].isoformat(),
                        "s3_uri": f"s3://{self.bucket_name}/{obj['Key']}",
                    })
                return reports
            except Exception:
                pass

        # Read from local mock storage
        mock_reports_dir = self.local_mock_dir / self.bucket_name / "reports"
        if mock_reports_dir.exists():
            for p in mock_reports_dir.rglob("*"):
                if p.is_file():
                    rel = p.relative_to(self.local_mock_dir / self.bucket_name)
                    key = str(rel).replace("\\", "/")
                    reports.append({
                        "key": key,
                        "size": p.stat().st_size,
                        "last_modified": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat(),
                        "s3_uri": f"s3://{self.bucket_name}/{key}",
                    })
        return reports
