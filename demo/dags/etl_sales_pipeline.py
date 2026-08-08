"""
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
