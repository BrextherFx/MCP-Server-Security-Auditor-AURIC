# ☁️ AWS S3 Bucket & Cloud Sync Complete Setup Guide
## MCP Server Security Auditor (PS02)

This guide walks you step-by-step through setting up an **Amazon Web Services (AWS) S3 Bucket**, generating your **IAM Access Keys**, configuring the **`.env`** file, and verifying both cloud and local simulation modes.

---

## 📌 Architecture: Why SQLite + AWS S3?

```
┌───────────────────────────────────────┐
│         LOCAL AUDITOR RUNTIME         │
│                                       │
│   SQLite Database (mcpaudit_pins.db)  │  ◄── Microsecond checks, zero network latency
│   • Approved SHA-256 Tool Fingerprints│
│   • Audit Scan History                │
└──────────────────┬────────────────────┘
                   │
         Bidirectional Cloud Sync (boto3)
                   │
┌──────────────────▼────────────────────┐
│          AWS S3 CLOUD VAULT           │
│                                       │
│   s3://{bucket-name}/                 │
│   ├── databases/                      │  ◄── Central baseline distribution
│   │   └── mcpaudit_pins.db            │
│   └── reports/{server_id}/            │  ◄── Immutable compliance archive
│       ├── 20261016_audit.html         │
│       ├── 20261016_audit.sarif        │
│       └── 20261016_audit.md           │
└───────────────────────────────────────┘
```

- **Local SQLite (`mcpaudit_pins.db`)**: Ensures security auditing runs in microseconds inside CI/CD containers or developer laptops without internet dependence.
- **AWS S3 Cloud**: Provides a centralized, tamper-resistant cloud backup of approved baselines and historical compliance reports across teams.
- **Zero-Cost Local Simulation Fallback**: If AWS keys are not configured, MCPAudit automatically creates `./s3_bucket_storage/{bucket}/` locally so demonstrations never fail!

---

## 🛠️ Step 1: Create an AWS S3 Bucket

1. Log into your [AWS Management Console](https://aws.amazon.com/console/).
2. In the top search bar, type **S3** and click **S3 (Scalable Storage in the Cloud)**.
3. Click the orange **Create bucket** button.
4. Configure bucket settings:
   - **Bucket name**: Enter a unique name in lowercase with hyphens (e.g., `mcpaudit-vault-yourname` or `mcp-security-auditor-vault`).
     > *Note: S3 bucket names must be globally unique across all AWS accounts.*
   - **AWS Region**: Select your nearest region (e.g., `us-east-1` (US East N. Virginia) or `ap-south-1` (Asia Pacific Mumbai)).
   - **Block Public Access settings for this bucket**: Leave **Block all public access** checked ✅ (Recommended for security; MCPAudit connects via authenticated API keys).
   - **Bucket Versioning**: Optional (Disabled or Enabled).
   - **Default encryption**: Leave as **Amazon S3 managed keys (SSE-S3)**.
5. Scroll to the bottom and click **Create bucket**.

---

## 🔑 Step 2: Get Your AWS Access Key ID & Secret Access Key

To allow MCPAudit to read and write to your S3 bucket, create an IAM user:

1. In the top search bar of AWS Console, type **IAM** and select **IAM (Manage access to AWS resources)**.
2. In the left navigation menu, click **Users** $\rightarrow$ click the blue **Create user** button.
3. **Step 1 - User details**:
   - Username: `mcpaudit-agent` (or any name you prefer).
   - Do NOT check "Provide user access to the AWS Management Console" (this is a programmatic service user).
   - Click **Next**.
4. **Step 2 - Set permissions**:
   - Select **Attach policies directly**.
   - In the permissions search box, type `AmazonS3FullAccess`.
   - Check the box next to **`AmazonS3FullAccess`** ✅.
   - Click **Next**.
5. **Step 3 - Review and create**:
   - Click **Create user**.
6. **Generate Credentials**:
   - Click on your newly created user (`mcpaudit-agent`).
   - Click on the **Security credentials** tab.
   - Scroll down to the **Access keys** section and click **Create access key**.
   - Select **Command Line Interface (CLI)** or **Local code**.
   - Check the confirmation box: *"I understand the above recommendation..."* and click **Next**.
   - (Optional) Description tag: `MCPAudit CLI and Web Studio`.
   - Click **Create access key**.
7. **Copy Keys**:
   - You will see:
     - **Access key**: (Starts with `AKIA...`, e.g. `AKIAIOSFODNN7EXAMPLE`)
     - **Secret access key**: (40-character secret string)
   - Click **Download .csv file** or copy both keys immediately. 
   > ⚠️ *Important: You will never be able to view the secret access key again after closing this window.*

---

## ⚙️ Step 3: Configure Your `.env` File

Open the `.env` file in the project root (`c:\Users\thril\Desktop\Hackthon\.env`) and paste your credentials:

```env
# ==============================================================================
# AWS S3 BUCKET & SQLITE CLOUD SYNCHRONIZATION
# ==============================================================================
AWS_ACCESS_KEY_ID=AKIAxxxxxxxxxxxxxxxx
AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_REGION=us-east-1
AWS_S3_BUCKET=your-bucket-name-here

# ==============================================================================
# LOCAL LLM (LM STUDIO) CONFIGURATION
# ==============================================================================
LM_STUDIO_URL=http://localhost:1234/v1
LM_STUDIO_MODEL=qwen2.5-3b-instruct

# ==============================================================================
# WEB STUDIO PORT
# ==============================================================================
MCPAUDIT_PORT=8000
MCPAUDIT_HOST=127.0.0.1
```

Save the `.env` file. MCPAudit automatically loads these variables on startup!

---

## 💡 Step 4: Zero-Cost Local Simulation (No AWS Account Required)

If you are presenting at a hackathon without Wi-Fi, or don't want AWS cloud fees:

- **Simply leave `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` blank in `.env`:**
  ```env
  AWS_ACCESS_KEY_ID=
  AWS_SECRET_ACCESS_KEY=
  AWS_REGION=us-east-1
  AWS_S3_BUCKET=mcp-security-auditor-vault
  ```
- MCPAudit will automatically switch to **Local S3 Bucket Simulation**:
  - Pinned databases and reports will be saved into `./s3_bucket_storage/{bucket_name}/`.
  - All UI buttons, sync operations, and report downloads work 100% offline!

---

## 🧪 Step 5: Verify S3 & Report Downloads

### Method 1: Interactive Web Studio
1. Launch the web server:
   ```bash
   .\.venv\Scripts\mcpaudit serve --port 8000
   ```
2. Open **`http://127.0.0.1:8000`** in your browser.
3. Look at the top navigation bar:
   - Green badge: `S3: AWS (your-bucket)` (Live AWS Connected)
   - Amber badge: `S3: Emulated (mcp-security-auditor-vault)` (Local Simulation Active)
4. Click on the **☁️ Reports & S3 Cloud Sync** tab:
   - Click **Download .HTML**, **Download .SARIF**, or **Download .MD**.
   - Click **☁️ Sync SQLite Database to S3** $\rightarrow$ uploads `mcpaudit_pins.db`.
   - Click **📦 Archive Current Report to S3** $\rightarrow$ uploads report files into S3 vault.
   - Review your entries in the **SQLite Audit History** and **S3 Bucket Object Vault** tables!

### Method 2: Command Line (CLI)
```bash
# Scan and automatically sync SQLite & HTML report to AWS S3:
mcpaudit scan test_servers/clean_math_server.py --s3-sync --html audit.html

# Run the automated test suite verifying S3 sync:
.\.venv\Scripts\pytest tests/test_s3_storage.py -v
```

---

## 🚨 Troubleshooting Common Issues

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **`AccessDenied`** | IAM user does not have permission for the bucket. | Attach policy `AmazonS3FullAccess` to the IAM user in AWS IAM Console. |
| **`NoSuchBucket`** | The bucket name in `.env` does not match your AWS S3 bucket. | Double check bucket spelling in `.env` or create the bucket in the same region. |
| **`404 Not Found` in Web UI** | An old web server process was still running on port 8000. | Restart the web server with `mcpaudit serve --port 8000`. |
| **LM Studio Offline** | LM Studio local server is not started. | Open LM Studio, load `qwen2.5-3b-instruct`, and click **Start Server** on port 1234. |
