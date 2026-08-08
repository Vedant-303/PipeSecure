"""
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
