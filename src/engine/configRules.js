/**
 * PipeSecure — Infrastructure Configuration Rules (Phase 2)
 *
 * Detects storage access misconfigurations (S3 bucket policies, IAM policies),
 * and missing encryption-at-rest settings in pipeline infrastructure configs.
 *
 * Targets AWS patterns (S3, IAM, RDS, EBS) for v1.
 * GCP/Azure can be added as separate rule files later.
 *
 * Design notes:
 * - Some rules use multi-line regex ([\s\S]) for JSON policy documents
 * - Rules work across Terraform (.tf), CloudFormation (.yaml/.json), and raw policy JSON
 * - False positive filtering reuses the same comment-detection logic as secretRules
 */

import { Severity, Category } from './types.js';

/**
 * Check if a line is a comment (reused from secretRules pattern)
 */
function isComment(line) {
  const trimmed = line.trim();
  return trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('--');
}

/** ─── Storage & Access Rules ─── */

const storageAccessRules = [
  // ──────────────────────────────────────────────
  // CFG-001: S3 Bucket Policy — Public Read Access
  // ──────────────────────────────────────────────
  {
    id: 'CFG-001',
    category: Category.STORAGE_ACCESS,
    severity: Severity.CRITICAL,
    title: 'S3 bucket policy allows public read access',
    pattern: /"Principal"\s*:\s*(?:"\*"|\{"AWS"\s*:\s*"\*"\})[\s\S]{0,500}(?:s3:GetObject|s3:\*)/gi,
    fileTypes: ['.json', '.yaml', '.yml', '.tf', '.hcl'],
    validate: (line) => !isComment(line),
    exposed: () =>
      `An S3 bucket policy grants read access to everyone on the internet (Principal: "*"). Anyone with the bucket URL can download objects from this bucket.`,
    whyItMatters:
      'If this bucket stores pipeline data, logs, or intermediate results, making it publicly readable means anyone on the internet can access that data. Data breaches from misconfigured S3 buckets are among the most common cloud security incidents — they\'ve exposed millions of records at companies of all sizes.',
    remediation:
      'Restrict the Principal to specific AWS accounts or IAM roles that need access. Use S3 Block Public Access at the account level as an extra safety net.',
    remediationCode: () =>
      `// Restrict to specific IAM roles instead of public access:
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::123456789012:role/ETLServiceRole"
    },
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*"
  }]
}

// Also enable S3 Block Public Access:
// aws s3api put-public-access-block --bucket my-bucket \\
//   --public-access-block-configuration \\
//   BlockPublicAcls=true,IgnorePublicAcls=true,\\
//   BlockPublicPolicy=true,RestrictPublicBuckets=true`,
  },

  // ──────────────────────────────────────────────
  // CFG-002: S3 Bucket Policy — Public Write/Delete
  // ──────────────────────────────────────────────
  {
    id: 'CFG-002',
    category: Category.STORAGE_ACCESS,
    severity: Severity.CRITICAL,
    title: 'S3 bucket policy allows public write or delete',
    pattern: /"Principal"\s*:\s*(?:"\*"|\{"AWS"\s*:\s*"\*"\})[\s\S]{0,500}(?:s3:PutObject|s3:DeleteObject)/gi,
    fileTypes: ['.json', '.yaml', '.yml', '.tf', '.hcl'],
    validate: (line) => !isComment(line),
    exposed: () =>
      `An S3 bucket policy grants write or delete permissions to everyone (Principal: "*"). Anyone can upload, overwrite, or delete objects in this bucket.`,
    whyItMatters:
      'Public write access means attackers can inject malicious data into your pipeline, replace legitimate files with corrupted ones, or delete your data entirely. This is especially dangerous for data pipelines that automatically process whatever lands in a bucket — an attacker could inject poisoned data that flows through your entire pipeline.',
    remediation:
      'Remove the wildcard Principal immediately. Restrict write/delete access to only the specific IAM roles your pipeline uses.',
    remediationCode: () =>
      `// Restrict write access to your pipeline's IAM role only:
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::123456789012:role/ETLWriterRole"
    },
    "Action": ["s3:PutObject"],
    "Resource": "arn:aws:s3:::my-pipeline-bucket/*"
  }]
}`,
  },

  // ──────────────────────────────────────────────
  // CFG-003: S3 Bucket ACL — Public Read/Write
  // ──────────────────────────────────────────────
  {
    id: 'CFG-003',
    category: Category.STORAGE_ACCESS,
    severity: Severity.HIGH,
    title: 'S3 bucket ACL set to public access',
    pattern: /(?:acl|canned_acl|x-amz-acl)\s*[=:]\s*['"]?(public-read-write|public-read|authenticated-read)['"]?/gi,
    fileTypes: ['.tf', '.hcl', '.yaml', '.yml', '.json', '.py', '.cfg'],
    validate: (line) => !isComment(line),
    exposed: (match) =>
      `An S3 bucket or object ACL is set to "${match[1]}", which grants ${match[1] === 'public-read-write' ? 'read and write' : 'read'} access to ${match[1] === 'authenticated-read' ? 'any authenticated AWS user (not just your account)' : 'anyone on the internet'}.`,
    whyItMatters:
      'Bucket ACLs are a legacy access control mechanism that\'s easy to misconfigure. "public-read" and "public-read-write" make your data accessible to anyone with the URL. AWS recommends using bucket policies with S3 Block Public Access instead of ACLs.',
    remediation:
      'Change the ACL to "private" and use bucket policies with specific IAM principals for access control. Enable S3 Block Public Access on the bucket and account.',
    remediationCode: () =>
      `# Terraform — set private ACL and enable Block Public Access:
resource "aws_s3_bucket" "pipeline_data" {
  bucket = "my-pipeline-data"
}

resource "aws_s3_bucket_acl" "pipeline_data" {
  bucket = aws_s3_bucket.pipeline_data.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "pipeline_data" {
  bucket = aws_s3_bucket.pipeline_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
  },

  // ──────────────────────────────────────────────
  // CFG-004: IAM Policy — Wildcard Action (Admin)
  // ──────────────────────────────────────────────
  {
    id: 'CFG-004',
    category: Category.STORAGE_ACCESS,
    severity: Severity.CRITICAL,
    title: 'IAM policy grants wildcard actions (admin-level)',
    pattern: /"Action"\s*:\s*(?:"\*"|\[[\s\S]{0,50}"\*"[\s\S]{0,50}\])/gi,
    fileTypes: ['.json', '.yaml', '.yml', '.tf', '.hcl'],
    validate: (line) => !isComment(line),
    exposed: () =>
      `An IAM policy grants wildcard ("*") actions, meaning it allows every possible AWS API action. This is equivalent to full administrator access.`,
    whyItMatters:
      'Data pipeline IAM roles should only have the specific permissions they need (e.g., s3:GetObject, s3:PutObject, redshift:GetClusterCredentials). Granting "*" means that if the pipeline\'s credentials are compromised, an attacker can do anything in your AWS account — create users, delete resources, access billing, and exfiltrate all data.',
    remediation:
      'Replace the wildcard action with the minimum set of actions your pipeline actually needs. Use the AWS Access Advisor or CloudTrail to determine which actions are used.',
    remediationCode: () =>
      `// Apply least-privilege — list only the actions your pipeline needs:
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
      "redshift:GetClusterCredentials",
      "glue:GetTable",
      "glue:GetDatabase"
    ],
    "Resource": [
      "arn:aws:s3:::my-pipeline-bucket/*",
      "arn:aws:redshift:us-east-1:123456789012:*"
    ]
  }]
}`,
  },

  // ──────────────────────────────────────────────
  // CFG-005: IAM Policy — Wildcard Resource
  // ──────────────────────────────────────────────
  {
    id: 'CFG-005',
    category: Category.STORAGE_ACCESS,
    severity: Severity.HIGH,
    title: 'IAM policy grants access to all resources',
    pattern: /"Resource"\s*:\s*(?:"\*"|\[[\s\S]{0,50}"\*"[\s\S]{0,50}\])/gi,
    fileTypes: ['.json', '.yaml', '.yml', '.tf', '.hcl'],
    validate: (line) => !isComment(line),
    exposed: () =>
      `An IAM policy sets Resource to "*", meaning the granted actions apply to every resource in the AWS account (all S3 buckets, all databases, all Lambda functions, etc.).`,
    whyItMatters:
      'Even if the actions are scoped (e.g., only s3:GetObject), a wildcard resource means the role can read from every S3 bucket in the account — including buckets with PII, financial data, or other teams\' sensitive data. This violates the principle of least privilege and increases blast radius if credentials are compromised.',
    remediation:
      'Scope the Resource to the specific ARNs your pipeline needs (e.g., specific S3 bucket ARNs, specific Redshift cluster ARNs).',
    remediationCode: () =>
      `// Scope to specific resources instead of wildcard:
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": [
      "arn:aws:s3:::pipeline-staging-bucket/*",
      "arn:aws:s3:::pipeline-output-bucket/*"
    ]
  }]
}`,
  },

  // ──────────────────────────────────────────────
  // CFG-006: IAM Policy — Overly Broad S3 Actions
  // ──────────────────────────────────────────────
  {
    id: 'CFG-006',
    category: Category.STORAGE_ACCESS,
    severity: Severity.HIGH,
    title: 'IAM policy grants overly broad S3 permissions',
    pattern: /"Action"\s*:\s*(?:"s3:\*"|\[[\s\S]{0,200}"s3:\*"[\s\S]{0,200}\])/gi,
    fileTypes: ['.json', '.yaml', '.yml', '.tf', '.hcl'],
    validate: (line) => !isComment(line),
    exposed: () =>
      `An IAM policy grants "s3:*" — every possible S3 action including deleting buckets, changing policies, and disabling encryption.`,
    whyItMatters:
      'Most data pipelines only need s3:GetObject and s3:PutObject. Granting s3:* also includes dangerous actions like s3:DeleteBucket, s3:PutBucketPolicy (which could make buckets public), and s3:PutEncryptionConfiguration (which could disable encryption). It\'s a common shortcut that creates unnecessary risk.',
    remediation:
      'Replace s3:* with the specific S3 actions your pipeline actually uses.',
    remediationCode: () =>
      `// Replace s3:* with specific needed actions:
{
  "Action": [
    "s3:GetObject",
    "s3:PutObject",
    "s3:ListBucket"
  ]
}

// Common S3 actions for pipelines:
// s3:GetObject      — read files
// s3:PutObject      — write files
// s3:ListBucket     — list contents
// s3:DeleteObject   — only if pipeline cleans up after itself`,
  },

  // ──────────────────────────────────────────────
  // CFG-007: S3 Bucket — Missing Versioning/Logging
  // ──────────────────────────────────────────────
  {
    id: 'CFG-007',
    category: Category.STORAGE_ACCESS,
    severity: Severity.MEDIUM,
    title: 'S3 bucket missing versioning or access logging',
    pattern: /resource\s+["']aws_s3_bucket["']\s+["'](\w+)["']\s*\{(?:(?!versioning|logging)[\s\S]){20,}?\}/gi,
    fileTypes: ['.tf', '.hcl'],
    validate: (line) => !isComment(line),
    exposed: (match) =>
      `An S3 bucket resource "${match[1]}" is defined without versioning or access logging enabled.`,
    whyItMatters:
      'Without versioning, if pipeline data is accidentally overwritten or deleted, there\'s no way to recover it. Without access logging, you can\'t audit who accessed the data or detect unauthorized access. Both are essential for data pipeline reliability and security.',
    remediation:
      'Enable versioning and server access logging on the bucket.',
    remediationCode: (match) =>
      `# Enable versioning and logging for the bucket:
resource "aws_s3_bucket_versioning" "${match[1]}" {
  bucket = aws_s3_bucket.${match[1]}.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "${match[1]}" {
  bucket        = aws_s3_bucket.${match[1]}.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "${match[1]}/"
}`,
  },
];

/** ─── Encryption Rules ─── */

const encryptionRules = [
  // ──────────────────────────────────────────────
  // ENC-001: S3 Bucket — Missing Server-Side Encryption
  // ──────────────────────────────────────────────
  {
    id: 'ENC-001',
    category: Category.ENCRYPTION,
    severity: Severity.HIGH,
    title: 'S3 bucket missing server-side encryption',
    pattern: /resource\s+["']aws_s3_bucket["']\s+["'](\w+)["']\s*\{(?:(?!server_side_encryption|aws_s3_bucket_server_side_encryption)[\s\S]){20,}?\}/gi,
    fileTypes: ['.tf', '.hcl'],
    validate: (line) => !isComment(line),
    exposed: (match) =>
      `An S3 bucket "${match[1]}" is configured without server-side encryption. Data stored in this bucket is not encrypted at rest.`,
    whyItMatters:
      'Encryption at rest protects your data if the storage media is physically compromised or if someone gains unauthorized access to the underlying storage. For data pipelines handling PII, financial data, or other sensitive information, encryption at rest is often a compliance requirement (SOC 2, HIPAA, GDPR).',
    remediation:
      'Enable server-side encryption using AWS KMS (SSE-KMS) or S3-managed keys (SSE-S3).',
    remediationCode: (match) =>
      `# Enable server-side encryption with AWS KMS:
resource "aws_s3_bucket_server_side_encryption_configuration" "${match[1]}" {
  bucket = aws_s3_bucket.${match[1]}.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.pipeline_key.arn
    }
    bucket_key_enabled = true
  }
}`,
  },

  // ──────────────────────────────────────────────
  // ENC-002: RDS/Redshift — Storage Encryption Disabled
  // ──────────────────────────────────────────────
  {
    id: 'ENC-002',
    category: Category.ENCRYPTION,
    severity: Severity.HIGH,
    title: 'Database storage encryption is disabled',
    pattern: /(?:storage_encrypted|StorageEncrypted|encrypted)\s*[=:]\s*(?:false|"false"|False)/gi,
    fileTypes: ['.tf', '.hcl', '.yaml', '.yml', '.json'],
    validate: (line) => !isComment(line),
    exposed: () =>
      `A database instance (RDS, Redshift, or similar) has storage encryption explicitly disabled. Data stored in this database is not encrypted at rest.`,
    whyItMatters:
      'Database instances store the data your pipeline produces and consumes. Without encryption at rest, the data on the physical storage disks is unprotected. This is a common compliance violation and leaves data vulnerable if AWS infrastructure is physically compromised.',
    remediation:
      'Set storage_encrypted to true. Note: for existing RDS instances, you cannot enable encryption in-place — you need to create an encrypted snapshot and restore from it.',
    remediationCode: () =>
      `# Terraform — enable storage encryption:
resource "aws_db_instance" "pipeline_db" {
  # ... other settings ...
  storage_encrypted = true
  kms_key_id        = aws_kms_key.pipeline_key.arn
}

# For Redshift:
resource "aws_redshift_cluster" "analytics" {
  # ... other settings ...
  encrypted  = true
  kms_key_id = aws_kms_key.pipeline_key.arn
}`,
  },

  // ──────────────────────────────────────────────
  // ENC-003: EBS Volume — Encryption Not Enabled
  // ──────────────────────────────────────────────
  {
    id: 'ENC-003',
    category: Category.ENCRYPTION,
    severity: Severity.MEDIUM,
    title: 'EBS volume without encryption',
    pattern: /resource\s+["']aws_ebs_volume["']\s+["'](\w+)["']\s*\{(?:(?!encrypted\s*=\s*true)[\s\S]){10,}?\}/gi,
    fileTypes: ['.tf', '.hcl'],
    validate: (line) => !isComment(line),
    exposed: (match) =>
      `An EBS volume "${match[1]}" is defined without encryption enabled. Data stored on this volume is not encrypted at rest.`,
    whyItMatters:
      'EBS volumes attached to EC2 instances running pipeline workers (Airflow workers, Spark executors, etc.) may contain temporary pipeline data, cached datasets, or log files with sensitive information. Unencrypted EBS volumes leave this data exposed.',
    remediation:
      'Add encrypted = true to the EBS volume configuration. You can also enable default EBS encryption at the account level so all new volumes are automatically encrypted.',
    remediationCode: (match) =>
      `# Enable encryption on the EBS volume:
resource "aws_ebs_volume" "${match[1]}" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
  kms_key_id        = aws_kms_key.pipeline_key.arn

  tags = {
    Name = "${match[1]}"
  }
}

# Or enable default encryption for all new EBS volumes:
# aws ec2 enable-ebs-encryption-by-default --region us-east-1`,
  },

  // ──────────────────────────────────────────────
  // ENC-004: Database Connection — SSL/TLS Not Enforced
  // ──────────────────────────────────────────────
  {
    id: 'ENC-004',
    category: Category.ENCRYPTION,
    severity: Severity.MEDIUM,
    title: 'Database connection without SSL/TLS enforcement',
    pattern: /(?:sslmode|ssl_mode|SSL_MODE)\s*[=:]\s*['"]?(disable|allow|prefer)['"]?/gi,
    fileTypes: ['.py', '.yaml', '.yml', '.json', '.toml', '.cfg', '.ini', '.conf', '.env'],
    validate: (line) => !isComment(line),
    exposed: (match) =>
      `A database connection is configured with SSL mode "${match[1]}", which ${match[1] === 'disable' ? 'completely disables encryption for data in transit' : 'does not require encryption, allowing unencrypted fallback'}.`,
    whyItMatters:
      'Without SSL/TLS enforcement, data transferred between your pipeline and the database travels unencrypted over the network. This includes query results, credentials, and sensitive data. On shared networks or across the internet, this data can be intercepted by anyone monitoring network traffic.',
    remediation:
      'Set SSL mode to "require" (minimum) or "verify-full" (recommended) to ensure all database connections use encrypted transport.',
    remediationCode: () =>
      `# Set SSL mode to require or verify-full:

# In connection string:
# postgresql://user:pass@host:5432/db?sslmode=verify-full

# In Python (psycopg2):
conn = psycopg2.connect(
    host="db-host",
    sslmode="verify-full",
    sslrootcert="/path/to/ca-cert.pem"
)

# In YAML config:
database:
  sslmode: "verify-full"
  sslrootcert: "/path/to/ca-cert.pem"`,
  },
];

/** Combined config rules (storage + encryption) */
const configRules = [...storageAccessRules, ...encryptionRules];

export default configRules;
export { storageAccessRules, encryptionRules };
