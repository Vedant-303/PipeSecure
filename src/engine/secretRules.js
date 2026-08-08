/**
 * PipeSecure — Pipeline-Specific Secret Detection Rules (Phase 1)
 *
 * Each rule targets a specific credential pattern commonly found in data pipeline
 * artifacts (Airflow DAGs, dbt profiles, ETL scripts, config YAMLs).
 *
 * Design notes:
 * - Patterns use capturing groups to isolate the secret portion for masking.
 * - `validate` functions reduce false positives by checking for common non-secret patterns
 *   (e.g., environment variable lookups, placeholder strings, commented lines).
 * - `exposed` / `whyItMatters` / `remediation` are written in plain language for
 *   non-security engineers.
 */

import { Severity, Category } from './types.js';

/** Common false-positive indicators to filter out */
const FALSE_POSITIVE_INDICATORS = [
  'os.environ',
  'os.getenv',
  'env(',
  'ENV[',
  'process.env',
  'Variable(',
  'Secret(',
  'ssm:',
  'vault:',
  'arn:aws:secretsmanager',
  '${',
  '{{',
  '<your_',
  '<YOUR_',
  'PLACEHOLDER',
  'placeholder',
  'example.com',
  'xxx',
  'XXX',
  'TODO',
  'CHANGEME',
  'change_me',
  'your_password',
  'your_api_key',
  'INSERT_',
];

/**
 * Check if a line is a comment
 */
function isComment(line) {
  const trimmed = line.trim();
  return trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('--');
}

/**
 * Check if match context suggests a false positive
 */
function isFalsePositive(line, matchStr) {
  if (isComment(line)) return true;
  const combined = line + matchStr;
  return FALSE_POSITIVE_INDICATORS.some(fp => combined.includes(fp));
}

/** ─── Secret Detection Rules ─── */

const secretRules = [
  // ──────────────────────────────────────────────
  // SEC-001: Database Connection Strings with Embedded Credentials
  // ──────────────────────────────────────────────
  {
    id: 'SEC-001',
    category: Category.SECRETS,
    severity: Severity.CRITICAL,
    title: 'Database connection string with embedded credentials',
    pattern: /(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redshift|snowflake|mssql|oracle):\/\/([^:\s]+):([^@\s]{3,})@([^\/\s:]+)/gi,
    fileTypes: ['.py', '.yaml', '.yml', '.json', '.toml', '.cfg', '.ini', '.conf', '.env', '.sql', '.sh'],
    validate: (line, match) => !isFalsePositive(line, match[0]),
    exposed: (match) =>
      `A database connection string contains a hardcoded username ("${match[1]}") and password in plain text, connecting to host "${match[3]}".`,
    whyItMatters:
      'Anyone with access to this file (version control, CI logs, shared drives) can see the database password in plain text and use it to access your database directly. If this file is committed to Git, the password is permanently in your repo history even if you delete it later.',
    remediation:
      'Move the credentials to environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.), and reference them at runtime instead of embedding them in code.',
    remediationCode: (match) =>
      `# Instead of hardcoding the connection string:\nimport os\n\ndb_user = os.environ["DB_USER"]\ndb_password = os.environ["DB_PASSWORD"]\ndb_host = os.environ["DB_HOST"]\n\nconn_string = f"${match[0].split('://')[0]}://{db_user}:{db_password}@{db_host}/mydb"`,
  },

  // ──────────────────────────────────────────────
  // SEC-002: AWS Access Key ID
  // ──────────────────────────────────────────────
  {
    id: 'SEC-002',
    category: Category.SECRETS,
    severity: Severity.CRITICAL,
    title: 'Hardcoded AWS Access Key ID',
    pattern: /(?:aws_access_key_id|AWS_ACCESS_KEY_ID|AccessKeyId)\s*[=:]\s*['"]?(AKIA[0-9A-Z]{16})['"]?/gi,
    fileTypes: ['.py', '.yaml', '.yml', '.json', '.toml', '.cfg', '.ini', '.conf', '.env', '.sh', '.tf'],
    validate: (line, match) => !isFalsePositive(line, match[0]),
    exposed: (match) =>
      `An AWS Access Key ID ("${match[1].substring(0, 8)}…") is hardcoded in this file. AWS access keys grant programmatic access to your AWS account.`,
    whyItMatters:
      'AWS access keys are like a username+password for your AWS account. If this key pair is exposed, an attacker can spin up resources, access S3 buckets, read databases, or even delete your infrastructure — and you\'ll be billed for it.',
    remediation:
      'Remove the key from your code. Use IAM roles (for EC2/ECS/Lambda) or environment variables instead. Rotate this key immediately through the AWS IAM console since it may already be compromised.',
    remediationCode: () =>
      `# Use IAM roles (preferred) or environment variables:\nimport boto3\n\n# boto3 automatically uses IAM role credentials or\n# AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars\nclient = boto3.client('s3')  # No hardcoded keys needed`,
  },

  // ──────────────────────────────────────────────
  // SEC-003: AWS Secret Access Key
  // ──────────────────────────────────────────────
  {
    id: 'SEC-003',
    category: Category.SECRETS,
    severity: Severity.CRITICAL,
    title: 'Hardcoded AWS Secret Access Key',
    pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    fileTypes: ['.py', '.yaml', '.yml', '.json', '.toml', '.cfg', '.ini', '.conf', '.env', '.sh', '.tf'],
    validate: (line, match) => {
      if (isFalsePositive(line, match[0])) return false;
      // AWS secret keys are exactly 40 chars of base64-like characters
      return /^[A-Za-z0-9/+=]{40}$/.test(match[1]);
    },
    exposed: (match) =>
      `An AWS Secret Access Key is hardcoded in this file. This is the "password" half of an AWS access key pair.`,
    whyItMatters:
      'Combined with an Access Key ID, this secret key provides full programmatic access to your AWS account. Exposed secret keys are actively scanned for by automated bots and are typically exploited within minutes of being pushed to public repositories.',
    remediation:
      'Remove the secret key immediately. Use IAM roles for services running in AWS, or store secrets in AWS Secrets Manager. Rotate this key pair in the AWS IAM console right away.',
    remediationCode: () =>
      `# Never hardcode AWS secret keys. Use IAM roles or env vars:\n# For local development:\n# export AWS_SECRET_ACCESS_KEY="your-key"  (set in shell, not in code)\n\n# For AWS services, attach an IAM role instead — zero keys needed.\nimport boto3\nclient = boto3.client('s3')  # Credentials auto-resolved`,
  },

  // ──────────────────────────────────────────────
  // SEC-004: Airflow Connection with Embedded Password
  // ──────────────────────────────────────────────
  {
    id: 'SEC-004',
    category: Category.SECRETS,
    severity: Severity.HIGH,
    title: 'Airflow connection with hardcoded password',
    pattern: /(?:AIRFLOW_CONN_\w+|airflow\.models\.Connection)\s*[=(]\s*['"]?(\w+:\/\/[^:\s]+:[^@\s]{3,}@[^\s'"]+)['"]?/gi,
    fileTypes: ['.py', '.yaml', '.yml', '.env', '.cfg', '.sh'],
    validate: (line, match) => !isFalsePositive(line, match[0]),
    exposed: (match) =>
      `An Apache Airflow connection string has a password embedded directly in its URI.`,
    whyItMatters:
      'Airflow connections often point to production databases, APIs, or cloud services. A hardcoded connection URI means anyone reading DAG files or environment configs can extract the credentials and access those external services directly.',
    remediation:
      'Use Airflow\'s built-in Connections UI or the "secrets backend" feature (e.g., AWS Secrets Manager backend) to store connection credentials securely, and reference them by connection ID in your DAGs.',
    remediationCode: () =>
      `# In your DAG, reference connections by ID (not by URI):\nfrom airflow.hooks.base import BaseHook\n\nconn = BaseHook.get_connection("my_database_conn")\n# Password is retrieved securely from Airflow's secrets backend\n\n# Configure a secrets backend in airflow.cfg:\n# [secrets]\n# backend = airflow.providers.amazon.aws.secrets.secrets_manager.SecretsManagerBackend`,
  },

  // ──────────────────────────────────────────────
  // SEC-005: GCP Service Account Key (JSON)
  // ──────────────────────────────────────────────
  {
    id: 'SEC-005',
    category: Category.SECRETS,
    severity: Severity.CRITICAL,
    title: 'GCP service account key embedded in code',
    pattern: /"type"\s*:\s*"service_account"[\s\S]{0,200}"private_key"\s*:\s*"(-----BEGIN[^"]+)"/gi,
    fileTypes: ['.json', '.py', '.yaml', '.yml'],
    validate: (line, match) => !isFalsePositive(line, match[0]),
    exposed: () =>
      `A Google Cloud Platform service account private key is embedded directly in this file. This key provides full API access as that service account.`,
    whyItMatters:
      'GCP service account keys don\'t expire and have the same permissions as the service account itself. If exposed, an attacker can impersonate this identity to access Cloud Storage, BigQuery, Pub/Sub, or any other GCP service the account has access to — indefinitely.',
    remediation:
      'Delete this key from your code and revoke it in the GCP IAM console. Use Workload Identity Federation (for CI/CD) or attached service accounts (for GCE/GKE/Cloud Run) instead of key files.',
    remediationCode: () =>
      `# Use Application Default Credentials instead of key files:\nfrom google.cloud import bigquery\n\n# Automatically uses attached service account or\n# GOOGLE_APPLICATION_CREDENTIALS env var\nclient = bigquery.Client()\n\n# For local development, use:\n# gcloud auth application-default login`,
  },

  // ──────────────────────────────────────────────
  // SEC-006: Databricks Personal Access Token
  // ──────────────────────────────────────────────
  {
    id: 'SEC-006',
    category: Category.SECRETS,
    severity: Severity.HIGH,
    title: 'Databricks personal access token in code',
    pattern: /(?:token|DATABRICKS_TOKEN|databricks_token)\s*[=:]\s*['"]?(dapi[a-zA-Z0-9_-]{20,36})['"]?/gi,
    fileTypes: ['.py', '.yaml', '.yml', '.json', '.toml', '.cfg', '.env', '.sh'],
    validate: (line, match) => !isFalsePositive(line, match[0]),
    exposed: (match) =>
      `A Databricks Personal Access Token ("dapi${match[1].substring(4, 12)}…") is hardcoded. This token grants API access to your Databricks workspace.`,
    whyItMatters:
      'Databricks tokens can be used to run notebooks, access data, manage clusters, and query tables. An exposed token gives an attacker direct access to your data lakehouse and any data it contains.',
    remediation:
      'Remove the token from code. Use Databricks service principals with OAuth for production workloads, or store the token in a secrets manager and load it via environment variables.',
    remediationCode: () =>
      `# Use environment variables instead of hardcoded tokens:\nimport os\nfrom databricks.sdk import WorkspaceClient\n\n# Token loaded from DATABRICKS_TOKEN env var automatically\nw = WorkspaceClient(\n    host=os.environ["DATABRICKS_HOST"]\n    # token auto-discovered from env\n)`,
  },

  // ──────────────────────────────────────────────
  // SEC-007: Slack Webhook URL
  // ──────────────────────────────────────────────
  {
    id: 'SEC-007',
    category: Category.SECRETS,
    severity: Severity.MEDIUM,
    title: 'Slack webhook URL hardcoded in code',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]{6,}\/B[A-Za-z0-9_]{6,}\/[A-Za-z0-9_-]{12,}/gi,
    fileTypes: ['.py', '.yaml', '.yml', '.json', '.toml', '.cfg', '.env', '.sh', '.tf'],
    validate: (line) => !isComment(line),
    exposed: () =>
      `A Slack incoming webhook URL is hardcoded. This URL can be used to post messages to your Slack channel.`,
    whyItMatters:
      'While Slack webhooks are "lower risk" than database credentials, an exposed webhook can be used to send phishing messages, spam, or misleading alerts to your team\'s Slack channel, posing a social engineering risk.',
    remediation:
      'Store the webhook URL in an environment variable or secrets manager. If you suspect it\'s been exposed, regenerate the webhook in Slack\'s app settings.',
    remediationCode: () =>
      `# Store webhook URL in an environment variable:\nimport os\nimport requests\n\nslack_webhook = os.environ["SLACK_WEBHOOK_URL"]\nrequests.post(slack_webhook, json={"text": "Pipeline complete!"})`,
  },

  // ──────────────────────────────────────────────
  // SEC-008: Generic API Key / Token Assignment
  // ──────────────────────────────────────────────
  {
    id: 'SEC-008',
    category: Category.SECRETS,
    severity: Severity.HIGH,
    title: 'API key or token hardcoded in assignment',
    pattern: /(?:api_key|apikey|api_token|access_token|auth_token|secret_key|private_key|app_key|app_secret)\s*[=:]\s*['"]([a-zA-Z0-9_\-./+=]{16,})['"](?!\s*\))/gi,
    fileTypes: ['.py', '.yaml', '.yml', '.json', '.toml', '.cfg', '.ini', '.conf', '.env', '.sh'],
    validate: (line, match) => {
      if (isFalsePositive(line, match[0])) return false;
      // Must look like a real key, not a placeholder or short string
      const val = match[1];
      if (val.length < 16) return false;
      // Check it's not all the same character
      if (new Set(val).size < 4) return false;
      return true;
    },
    exposed: (match) =>
      `An API key or access token (${match[1].length} characters) is assigned directly in code rather than loaded from a secure source.`,
    whyItMatters:
      'API keys and tokens typically grant access to external services (cloud providers, SaaS APIs, data sources). Hardcoded tokens in code are easily leaked through version control, logs, or file sharing, and can be used to impersonate your application.',
    remediation:
      'Move the key/token to environment variables or a secrets manager. Load it at runtime using os.environ (Python) or process.env (Node.js).',
    remediationCode: (match) => {
      const varName = match[0].split(/[=:]/)[0].trim().toUpperCase();
      return `# Move to environment variable:\nimport os\n\n${varName.toLowerCase()} = os.environ["${varName}"]\n\n# Set the env var in your deployment config, not in code:\n# export ${varName}="your-actual-key"`;
    },
  },

  // ──────────────────────────────────────────────
  // SEC-009: OpenAI API Key
  // ──────────────────────────────────────────────
  {
    id: 'SEC-009',
    category: Category.SECRETS,
    severity: Severity.HIGH,
    title: 'OpenAI API key hardcoded in code',
    pattern: /['"]?(sk-(?:proj-)?[A-Za-z0-9_-]{32,})['"]?/gi,
    fileTypes: ['.py', '.yaml', '.yml', '.json', '.toml', '.cfg', '.env', '.sh'],
    validate: (line, match) => {
      if (isFalsePositive(line, match[0])) return false;
      // Must start with sk- or sk-proj- and be reasonable length
      return match[1].length >= 40;
    },
    exposed: () =>
      `An OpenAI API key is present in this file. This key is billed to your OpenAI account and can be used to make API calls.`,
    whyItMatters:
      'OpenAI API keys are billed per use. An exposed key can result in unexpected charges to your account if someone uses it to make large-volume API calls. Additionally, it may expose your API usage patterns and any fine-tuned models.',
    remediation:
      'Remove the key from code and regenerate it in your OpenAI dashboard. Store the new key in an environment variable.',
    remediationCode: () =>
      `# Use environment variable:\nimport os\nfrom openai import OpenAI\n\nclient = OpenAI(\n    api_key=os.environ["OPENAI_API_KEY"]\n)\n\n# Set in your environment:\n# export OPENAI_API_KEY="sk-..."`,
  },

  // ──────────────────────────────────────────────
  // SEC-010: Password Assigned in Python/YAML
  // ──────────────────────────────────────────────
  {
    id: 'SEC-010',
    category: Category.SECRETS,
    severity: Severity.HIGH,
    title: 'Password hardcoded in configuration',
    pattern: /(?:password|passwd|pwd|db_password|DB_PASSWORD|database_password)\s*[=:]\s*['"]([^'"]{4,})['"](?!\s*\))/gi,
    fileTypes: ['.py', '.yaml', '.yml', '.json', '.toml', '.cfg', '.ini', '.conf', '.env', '.properties'],
    validate: (line, match) => {
      if (isFalsePositive(line, match[0])) return false;
      const val = match[1];
      // Must be a real password, not a placeholder
      if (val.length < 4) return false;
      if (/^[x*]+$/i.test(val)) return false;
      return true;
    },
    exposed: (match) =>
      `A password (${match[1].length} characters) is stored in plain text in this configuration file.`,
    whyItMatters:
      'Passwords stored in plain text in configuration files are easily discovered by anyone with file access. They\'re also captured in version control history, making them nearly impossible to fully revoke once committed.',
    remediation:
      'Replace the hardcoded password with a reference to an environment variable or secrets manager. Rotate the password immediately since it may already be in your Git history.',
    remediationCode: () =>
      `# Use environment variables or a secrets manager:\nimport os\n\npassword = os.environ["DB_PASSWORD"]\n\n# Or use a secrets manager:\n# import boto3\n# client = boto3.client('secretsmanager')\n# secret = client.get_secret_value(SecretId='my-db-password')`,
  },

  // ──────────────────────────────────────────────
  // SEC-011: Private Key File Content
  // ──────────────────────────────────────────────
  {
    id: 'SEC-011',
    category: Category.SECRETS,
    severity: Severity.CRITICAL,
    title: 'Private key embedded in file',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/gi,
    fileTypes: ['.py', '.yaml', '.yml', '.json', '.cfg', '.conf', '.env', '.pem', '.key', '.sh'],
    validate: (line) => !isComment(line),
    exposed: () =>
      `A private cryptographic key (RSA, EC, or similar) is embedded directly in this file.`,
    whyItMatters:
      'Private keys are used for authentication (SSH, TLS, JWT signing). An exposed private key allows an attacker to impersonate your service, decrypt communications, or gain SSH access to servers. Unlike passwords, private keys are often not rotated regularly, making exposure especially dangerous.',
    remediation:
      'Remove the private key from this file immediately. Store it in a dedicated secrets manager or use managed key services (AWS KMS, GCP Cloud KMS). If this key was committed to version control, consider it compromised and generate a new key pair.',
    remediationCode: () =>
      `# Load private key from a secure location:\nimport os\n\n# Option 1: Environment variable\nprivate_key = os.environ["PRIVATE_KEY"]\n\n# Option 2: Secrets manager\nimport boto3\nclient = boto3.client('secretsmanager')\nresponse = client.get_secret_value(SecretId='my-private-key')\nprivate_key = response['SecretString']\n\n# Option 3: Use managed KMS instead of raw keys\n# import boto3\n# kms = boto3.client('kms')\n# kms.sign(KeyId='alias/my-key', ...)`,
  },

  // ──────────────────────────────────────────────
  // SEC-012: JWT Token Hardcoded
  // ──────────────────────────────────────────────
  {
    id: 'SEC-012',
    category: Category.SECRETS,
    severity: Severity.MEDIUM,
    title: 'JWT token hardcoded in code',
    pattern: /['"]?(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})['"]?/gi,
    fileTypes: ['.py', '.yaml', '.yml', '.json', '.toml', '.cfg', '.env', '.sh', '.js'],
    validate: (line, match) => {
      if (isComment(line)) return false;
      // Must have 3 base64url parts separated by dots
      const parts = match[1].split('.');
      return parts.length === 3 && parts.every(p => p.length > 8);
    },
    exposed: () =>
      `A JSON Web Token (JWT) is hardcoded in this file. JWTs often contain authentication claims and session data.`,
    whyItMatters:
      'JWTs are used for authentication and authorization. A hardcoded JWT can be replayed to impersonate a user or service. Even expired JWTs may leak sensitive information in their payload (user IDs, roles, email addresses).',
    remediation:
      'Remove the hardcoded JWT. Tokens should be generated dynamically at runtime through proper authentication flows, not stored in source code.',
    remediationCode: () =>
      `# Generate JWTs at runtime, never hardcode them:\nimport jwt\nimport os\n\ntoken = jwt.encode(\n    {"sub": "service-account", "exp": datetime.utcnow() + timedelta(hours=1)},\n    os.environ["JWT_SECRET_KEY"],\n    algorithm="HS256"\n)`,
  },
];

export default secretRules;
