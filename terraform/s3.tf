resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "company-cloudtrail-logs-local"
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
