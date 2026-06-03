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
  "Name": {"S": "Ayman Djioui"},
  "CreditCard": {"S": "4532 1111 2222 8821"},
  "ExpiryDate": {"S": "12/27"},
  "SecretCode": {"S": "421"}
}
ITEM
}

resource "aws_dynamodb_table_item" "client_2" {
  table_name = aws_dynamodb_table.company_clients.name
  hash_key   = aws_dynamodb_table.company_clients.hash_key
  item = <<ITEM
{
  "ClientId": {"S": "client_002"},
  "Name": {"S": "Aymane Elouafi"},
  "CreditCard": {"S": "4916 5555 6666 3342"},
  "ExpiryDate": {"S": "08/26"},
  "SecretCode": {"S": "193"}
}
ITEM
}

resource "aws_dynamodb_table_item" "client_3" {
  table_name = aws_dynamodb_table.company_clients.name
  hash_key   = aws_dynamodb_table.company_clients.hash_key
  item = <<ITEM
{
  "ClientId": {"S": "client_003"},
  "Name": {"S": "Badr Jakout"},
  "CreditCard": {"S": "5399 3333 4444 7761"},
  "ExpiryDate": {"S": "03/28"},
  "SecretCode": {"S": "882"}
}
ITEM
}

resource "aws_dynamodb_table_item" "client_4" {
  table_name = aws_dynamodb_table.company_clients.name
  hash_key   = aws_dynamodb_table.company_clients.hash_key
  item = <<ITEM
{
  "ClientId": {"S": "client_004"},
  "Name": {"S": "Amine Chaker"},
  "CreditCard": {"S": "4532 7777 8888 4471"},
  "ExpiryDate": {"S": "06/28"},
  "SecretCode": {"S": "305"}
}
ITEM
}
