#!/bin/bash

set -e

API="http://localhost:3001"
EMAIL="test$(date +%s)@example.com"
PASSWORD="password123"

echo "=== Testing Notes API ==="
echo "Using email: $EMAIL"
echo

echo "1. Register"
REGISTER=$(curl -s -X POST "$API/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$EMAIL\", \"password\": \"$PASSWORD\"}")
echo "$REGISTER" | jq .
TOKEN=$(echo "$REGISTER" | jq -r '.access_token')
echo

echo "2. Get current user"
curl -s "$API/me" -H "Authorization: Bearer $TOKEN" | jq .
echo

echo "3. Create note"
curl -s -X POST "$API/notes" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"title": "My First Note", "content": "Hello from the test script!"}' | jq .
echo

echo "4. Create another note"
curl -s -X POST "$API/notes" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"title": "Second Note", "content": "Testing the API"}' | jq .
echo

echo "5. List all notes"
curl -s "$API/notes" -H "Authorization: Bearer $TOKEN" | jq .
echo

echo "6. Test invalid token rejected"
RESULT=$(curl -s "$API/notes" -H "Authorization: Bearer invalid_token")
if echo "$RESULT" | jq -e '.error' > /dev/null 2>&1; then
  echo "Correctly rejected invalid token"
else
  echo "ERROR: Should have rejected invalid token"
  exit 1
fi
echo

echo "=== All tests passed ==="
