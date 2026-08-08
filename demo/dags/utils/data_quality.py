"""
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
