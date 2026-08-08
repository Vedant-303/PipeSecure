# Demo Vulnerable Pipeline — PipeSecure Sample Project

This folder contains a sample insecure data engineering pipeline project designed for evaluating **PipeSecure**.

## Included Files & Subdirectories:
- `dags/etl_sales_pipeline.py` — Airflow DAG with hardcoded PostgreSQL URI, AWS AKIA keys, and Salesforce API key
- `dags/utils/data_quality.py` — Reusable data quality helper (clean reference code)
- `config/snowflake_config.yaml` — Snowflake database credentials in plain text
- `config/dbt_profiles.yml` — dbt profile with hardcoded Snowflake & Postgres passwords
- `config/database.yaml` — Warehouse connection settings with `sslmode: disable`
- `scripts/sync_redshift.py` — Redshift sync script with hardcoded cluster URI and JWT token
- `infra/s3_bucket_policy.json` — S3 bucket policy granting `Principal: "*"` public access
- `infra/iam_etl_role.json` — IAM policy granting wildcard `Action: "*"` and `Resource: "*"`
- `infra/main.tf` — Terraform script provisioning unencrypted S3 bucket, RDS instance (`storage_encrypted = false`), and EBS volume
- `.env` — Environment file containing Slack webhooks, OpenAI API key, Databricks token, and Redis password
- `requirements.txt` — Dependency manifest with vulnerable package versions (Airflow 2.5.0, PyYAML 6.0, cryptography 38.0.0)

You can drag & drop this entire `demo/` folder directly into PipeSecure to test client-side security scanning!
