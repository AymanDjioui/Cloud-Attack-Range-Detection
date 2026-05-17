resource "aws_dynamodb_table" "company_clients" {
  name           = "CompanyClients"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "ClientId"

  attribute {
    name = "ClientId"
    type = "S"
  }
}

# Add some fake sensitive user data for the attacker to exfiltrate
resource "aws_dynamodb_table_item" "client_1" {
  table_name = aws_dynamodb_table.company_clients.name
  hash_key   = aws_dynamodb_table.company_clients.hash_key
  item = <<ITEM
{
  "ClientId": {"S": "client_001"},
  "Name": {"S": "John Doe"},
  "CreditCard": {"S": "4532-1111-2222-3333"},
  "SecretCode": {"S": "094"}
}
ITEM
}

resource "aws_dynamodb_table_item" "client_2" {
  table_name = aws_dynamodb_table.company_clients.name
  hash_key   = aws_dynamodb_table.company_clients.hash_key
  item = <<ITEM
{
  "ClientId": {"S": "client_002"},
  "Name": {"S": "Jane Smith"},
  "CreditCard": {"S": "4532-9999-8888-7777"},
  "SecretCode": {"S": "443"}
}
ITEM
}
