# Create the IAM Role for the vulnerable NodeJS API
resource "aws_iam_role" "banking_api_role" {
  name = "banking-api-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# VULNERABILITY: We are giving the API server full AdministratorAccess!
# When the attacker exploits SSRF, they will inherit these God-mode permissions.
resource "aws_iam_role_policy_attachment" "vulnerable_permissions" {
  role       = aws_iam_role.banking_api_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
