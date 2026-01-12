#!/bin/bash

BASE_URL="http://localhost:8443"

echo "=== RockZero API Test ==="
echo ""

echo "1. Health Check..."
curl -s "$BASE_URL/health" | jq .
echo ""

echo "2. Register Super Admin..."
ADMIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@example.com",
    "password": "SecurePassword123!"
  }')

echo "$ADMIN_RESPONSE" | jq .
ADMIN_TOKEN=$(echo "$ADMIN_RESPONSE" | jq -r '.tokens.access_token')
echo "Admin Token: $ADMIN_TOKEN"
echo ""

echo "3. Generate Invite Code..."
INVITE_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/auth/invite" \
  -H "Authorization: Bearer $ADMIN_TOKEN")

echo "$INVITE_RESPONSE" | jq .
INVITE_CODE=$(echo "$INVITE_RESPONSE" | jq -r '.code')
echo "Invite Code: $INVITE_CODE"
echo ""

echo "4. Register Regular User with Invite Code..."
USER_RESPONSE=$(curl -s -X POST "$BASE_URL/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"user1\",
    \"email\": \"user1@example.com\",
    \"password\": \"UserPassword123!\",
    \"invite_code\": \"$INVITE_CODE\"
  }")

echo "$USER_RESPONSE" | jq .
USER_TOKEN=$(echo "$USER_RESPONSE" | jq -r '.tokens.access_token')
echo "User Token: $USER_TOKEN"
echo ""

echo "5. Upload Test File..."
echo "Hello RockZero!" > /tmp/test.txt
curl -s -X POST "$BASE_URL/api/v1/files" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -F "file=@/tmp/test.txt" | jq .
echo ""

echo "6. List Files..."
FILES_RESPONSE=$(curl -s "$BASE_URL/api/v1/files" \
  -H "Authorization: Bearer $USER_TOKEN")
echo "$FILES_RESPONSE" | jq .
FILE_ID=$(echo "$FILES_RESPONSE" | jq -r '.files[0].id')
echo ""

echo "7. Create Widget..."
curl -s -X POST "$BASE_URL/api/v1/widgets" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "widget_type": "clock",
    "title": "Desktop Clock",
    "config": {"format": "24h", "timezone": "UTC"},
    "position_x": 100,
    "position_y": 100,
    "width": 200,
    "height": 100
  }' | jq .
echo ""

echo "8. List Widgets..."
curl -s "$BASE_URL/api/v1/widgets" \
  -H "Authorization: Bearer $USER_TOKEN" | jq .
echo ""

echo "9. Create Media Item..."
if [ -n "$FILE_ID" ]; then
  curl -s -X POST "$BASE_URL/api/v1/media" \
    -H "Authorization: Bearer $USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"file_id\": \"$FILE_ID\",
      \"title\": \"Test File\",
      \"media_type\": \"document\"
    }" | jq .
fi
echo ""

echo "10. List Media..."
curl -s "$BASE_URL/api/v1/media" \
  -H "Authorization: Bearer $USER_TOKEN" | jq .
echo ""

echo "=== Test Complete ==="
