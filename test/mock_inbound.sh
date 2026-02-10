curl -X POST http://localhost:3001/api/inbound \
  -F "from=test@example.com" \
  -F "to=warden@armourmail.ai" \
  -F "subject=Hello from the outside" \
  -F "text=This is a test email body." \
  -F "dkim=pass" \
  -F "SPF=pass" \
  -F "envelope={\"to\":[\"warden@armourmail.ai\"],\"from\":\"test@example.com\"}"
