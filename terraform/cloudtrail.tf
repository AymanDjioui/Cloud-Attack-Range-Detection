# ══════════════════════════════════════════════════════════════
#  CloudTrail — Logs ALL AWS API calls to our S3 bucket
#  This is what the forwarder will poll to detect attacks
# ══════════════════════════════════════════════════════════════

resource "aws_cloudtrail" "main" {
  name                       = "company-audit-trail"
  s3_bucket_name             = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail      = true
  enable_logging             = true
  include_global_service_events = true

  # Log data events for S3 and DynamoDB
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}
