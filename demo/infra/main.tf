# Pipeline Infrastructure — Terraform Configuration
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
