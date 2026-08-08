/**
 * PipeSecure — Demo Pipeline Data
 *
 * A sample "vulnerable pipeline project" for instant evaluation of the scanner
 * without requiring users to upload their own files. Contains representative
 * security issues found in real data engineering projects.
 *
 * These files are intentionally insecure — they demonstrate the patterns
 * PipeSecure detects.
 */

const demoFiles = [
  // ──────────────────────────────────────────────
  // Airflow DAG with hardcoded credentials
  // ──────────────────────────────────────────────
  {
    path: 'dags/etl_sales_pipeline.py',
    name: 'etl_sales_pipeline.py',
    extension: '.py',
    content: `"""
ETL Sales Pipeline - Daily ingestion from Salesforce to Snowflake
Author: data-team@acme.co
"""
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.providers.snowflake.hooks.snowflake import SnowflakeHook
from datetime import datetime, timedelta
import requests
import psycopg2

# ⚠ Hardcoded database connection
WAREHOUSE_CONN = "postgresql://etl_user:SuperSecret123!@prod-warehouse.internal.acme.co:5432/analytics"

# ⚠ Hardcoded AWS credentials for S3 staging
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ⚠ Hardcoded API key for Salesforce
api_key = "sf_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"

default_args = {
    'owner': 'data-team',
    'depends_on_past': False,
    'email_on_failure': True,
    'email': ['data-alerts@acme.co'],
    'retries': 2,
    'retry_delay': timedelta(minutes=5),
}

dag = DAG(
    'etl_sales_daily',
    default_args=default_args,
    description='Daily sales data ingestion pipeline',
    schedule_interval='0 6 * * *',
    start_date=datetime(2024, 1, 1),
    catchup=False,
)

def extract_salesforce(**kwargs):
    """Pull data from Salesforce API"""
    headers = {"Authorization": f"Bearer {api_key}"}
    response = requests.get(
        "https://acme.my.salesforce.com/services/data/v58.0/query",
        headers=headers,
        params={"q": "SELECT Id, Amount, CloseDate FROM Opportunity WHERE CloseDate = TODAY"}
    )
    return response.json()

def load_to_warehouse(**kwargs):
    """Load transformed data into PostgreSQL warehouse"""
    conn = psycopg2.connect(WAREHOUSE_CONN)
    # ... loading logic ...
    conn.close()

extract_task = PythonOperator(task_id='extract_salesforce', python_callable=extract_salesforce, dag=dag)
load_task = PythonOperator(task_id='load_to_warehouse', python_callable=load_to_warehouse, dag=dag)

extract_task >> load_task
`,
  },

  // ──────────────────────────────────────────────
  // Snowflake config YAML with hardcoded credentials
  // ──────────────────────────────────────────────
  {
    path: 'config/snowflake_config.yaml',
    name: 'snowflake_config.yaml',
    extension: '.yaml',
    content: `# Snowflake connection configuration
# Used by dbt and custom ETL scripts

snowflake:
  account: acme-corp.us-east-1
  user: ETL_SERVICE_USER
  password: "SnowflakeP@ss2024!"
  database: ANALYTICS_PROD
  warehouse: ETL_WH_LARGE
  role: SYSADMIN
  schema: RAW_SALESFORCE

  # Connection settings
  client_session_keep_alive: true
  query_timeout: 300
  login_timeout: 60
`,
  },

  // ──────────────────────────────────────────────
  // .env file with assorted secrets
  // ──────────────────────────────────────────────
  {
    path: '.env',
    name: '.env',
    extension: '.env',
    content: `# Pipeline environment configuration
# WARNING: Do not commit this file to version control

# Slack notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T000000000/B000000000/mock_slack_webhook_token_demo_123456

# OpenAI for data quality descriptions
OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz

# Databricks workspace
DATABRICKS_TOKEN=dapi_mock_databricks_token_demo_9876543210
DATABRICKS_HOST=https://acme-corp.cloud.databricks.com

# Database
DB_PASSWORD="ProductionDbPass2024!"

# Redis cache
REDIS_URL=redis://default:CacheP@ssword99@redis-prod.internal.acme.co:6379/0
`,
  },

  // ──────────────────────────────────────────────
  // Redshift sync script with hardcoded connection
  // ──────────────────────────────────────────────
  {
    path: 'scripts/sync_redshift.py',
    name: 'sync_redshift.py',
    extension: '.py',
    content: `"""
Redshift Sync Script
Syncs transformed data from S3 staging to Redshift analytics cluster.
Runs nightly via cron.
"""
import boto3
import psycopg2
import os
import logging

logger = logging.getLogger(__name__)

# ⚠ Hardcoded Redshift connection string
REDSHIFT_CONN = "redshift://analytics_admin:R3dsh1ft$ecure!@acme-analytics.cyxyz12345.us-east-1.redshift.amazonaws.com:5439/analytics"

# ⚠ Using hardcoded JWT for internal API auth
INTERNAL_API_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJldGwtc2VydmljZSIsImV4cCI6MTcyMDAwMDAwMH0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

def get_redshift_connection():
    """Create Redshift connection"""
    return psycopg2.connect(REDSHIFT_CONN)

def sync_table(table_name, s3_path):
    """COPY data from S3 into Redshift table"""
    conn = get_redshift_connection()
    cursor = conn.cursor()
    
    copy_sql = f"""
        COPY {table_name}
        FROM '{s3_path}'
        IAM_ROLE 'arn:aws:iam::123456789012:role/RedshiftS3Access'
        FORMAT AS PARQUET;
    """
    
    cursor.execute(copy_sql)
    conn.commit()
    logger.info(f"Synced {table_name} from {s3_path}")
    
    cursor.close()
    conn.close()

if __name__ == "__main__":
    tables = [
        ("raw_orders", "s3://acme-data-lake/staging/orders/"),
        ("raw_customers", "s3://acme-data-lake/staging/customers/"),
        ("raw_products", "s3://acme-data-lake/staging/products/"),
    ]
    
    for table, path in tables:
        sync_table(table, path)
`,
  },

  // ──────────────────────────────────────────────
  // dbt profiles.yml with hardcoded credentials
  // ──────────────────────────────────────────────
  {
    path: 'config/dbt_profiles.yml',
    name: 'dbt_profiles.yml',
    extension: '.yml',
    content: `# dbt connection profiles
# ⚠ This file should NOT contain plain-text credentials

acme_analytics:
  target: prod
  outputs:
    prod:
      type: snowflake
      account: acme-corp.us-east-1
      user: DBT_SERVICE_USER
      password: "dbtPr0dP@ssword!"
      role: TRANSFORMER
      database: ANALYTICS_PROD
      warehouse: DBT_WH
      schema: TRANSFORMED
      threads: 8

    dev:
      type: postgres
      host: dev-warehouse.internal.acme.co
      user: dbt_dev
      password: "DevP@ss123"
      port: 5432
      dbname: analytics_dev
      schema: dbt_dev
      threads: 4
`,
  },

  // ──────────────────────────────────────────────
  // Clean file (no issues) — to show "clean" state
  // ──────────────────────────────────────────────
  {
    path: 'dags/utils/data_quality.py',
    name: 'data_quality.py',
    extension: '.py',
    content: `"""
Data Quality Checks Utility
Reusable quality checks for pipeline tasks.
"""
import os
import logging

logger = logging.getLogger(__name__)


def check_row_count(df, table_name, min_rows=1):
    """Validate minimum row count"""
    count = len(df)
    if count < min_rows:
        logger.warning(f"Row count check failed for {table_name}: {count} < {min_rows}")
        return False
    logger.info(f"Row count check passed for {table_name}: {count} rows")
    return True


def check_null_percentage(df, column, max_null_pct=5.0):
    """Check that null percentage is within threshold"""
    null_count = df[column].isnull().sum()
    total = len(df)
    pct = (null_count / total) * 100 if total > 0 else 0
    
    if pct > max_null_pct:
        logger.warning(f"Null check failed for {column}: {pct:.1f}% > {max_null_pct}%")
        return False
    return True


def get_connection_string():
    """Safely load connection string from environment"""
    # ✅ Correct pattern — loading from env var, not hardcoded
    return os.environ.get("DATABASE_URL")
`,
  },

  // ──────────────────────────────────────────────
  // requirements.txt (for Phase 3 dependency checks)
  // ──────────────────────────────────────────────
  {
    path: 'requirements.txt',
    name: 'requirements.txt',
    extension: '.txt',
    content: `# Pipeline dependencies
apache-airflow==2.5.0
dbt-core==1.4.0
dbt-snowflake==1.4.0
psycopg2-binary==2.9.5
boto3==1.26.0
requests==2.28.0
pandas==1.5.2
snowflake-connector-python==3.0.0
cryptography==38.0.0
PyYAML==6.0
redis==4.4.0
openai==0.27.0
`,
  },

  // ──────────────────────────────────────────────
  // S3 Bucket Policy with Public Access (Phase 2)
  // ──────────────────────────────────────────────
  {
    path: 'infra/s3_bucket_policy.json',
    name: 's3_bucket_policy.json',
    extension: '.json',
    content: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadForPipelineOutput",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::acme-pipeline-output/*"
    },
    {
      "Sid": "ETLWriteAccess",
      "Effect": "Allow",
      "Principal": "*",
      "Action": [
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::acme-pipeline-staging/*"
    }
  ]
}
`,
  },

  // ──────────────────────────────────────────────
  // IAM Policy with Overly Broad Permissions (Phase 2)
  // ──────────────────────────────────────────────
  {
    path: 'infra/iam_etl_role.json',
    name: 'iam_etl_role.json',
    extension: '.json',
    content: `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ETLFullS3Access",
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    },
    {
      "Sid": "ETLAdminFallback",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
`,
  },

  // ──────────────────────────────────────────────
  // Terraform Config with Missing Encryption (Phase 2)
  // ──────────────────────────────────────────────
  {
    path: 'infra/main.tf',
    name: 'main.tf',
    extension: '.tf',
    content: `# Pipeline Infrastructure — Terraform Configuration
# Provisions S3 buckets, RDS instance, and EBS volumes for ETL pipeline

provider "aws" {
  region = "us-east-1"
}

# ⚠ S3 bucket with public-read ACL and no encryption
resource "aws_s3_bucket" "pipeline_staging" {
  bucket = "acme-pipeline-staging"
}

resource "aws_s3_bucket_acl" "pipeline_staging_acl" {
  bucket = aws_s3_bucket.pipeline_staging.id
  acl    = "public-read"
}

# ⚠ RDS instance with encryption disabled
resource "aws_db_instance" "pipeline_warehouse" {
  identifier     = "pipeline-warehouse"
  engine         = "postgres"
  engine_version = "14.7"
  instance_class = "db.r6g.xlarge"
  allocated_storage = 500

  db_name  = "analytics"
  username = "etl_admin"
  password = "TerraformDbP@ss2024!"

  storage_encrypted = false

  skip_final_snapshot = true
}

# ⚠ EBS volume without encryption
resource "aws_ebs_volume" "pipeline_worker_data" {
  availability_zone = "us-east-1a"
  size              = 200
  type              = "gp3"

  tags = {
    Name = "pipeline-worker-data"
  }
}

# Output bucket — properly configured (no findings expected)
resource "aws_s3_bucket" "pipeline_output" {
  bucket = "acme-pipeline-output-secure"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "pipeline_output" {
  bucket = aws_s3_bucket.pipeline_output.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
`,
  },

  // ──────────────────────────────────────────────
  // Database config with SSL disabled (Phase 2)
  // ──────────────────────────────────────────────
  {
    path: 'config/database.yaml',
    name: 'database.yaml',
    extension: '.yaml',
    content: `# Database connection settings for pipeline components

warehouse:
  host: prod-warehouse.internal.acme.co
  port: 5432
  database: analytics
  sslmode: disable
  connection_timeout: 30
  query_timeout: 300

staging_db:
  host: staging-db.internal.acme.co
  port: 5432
  database: staging
  sslmode: prefer
  connection_timeout: 15
`,
  },
];

export default demoFiles;
