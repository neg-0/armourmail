# Guard Protocol (v0.1)

The "Guard" is the gateway logic for ArmourMail. It determines if an incoming email should be processed or discarded.

## 1. Authentication
- **Sender Validation**: Only emails from known domains or specific allowed addresses are processed.
- **DKIM/SPF**: Verification must pass (SendGrid provides these fields).

## 2. Parsing Logic
- **Recipient Routing**: Extract the `to` address to identify the target agent.
- **Payload Extraction**:
    - `text`: Primary instruction body.
    - `html`: Fallback for rich content.
    - `attachments`: File inputs for agents.

## 3. Storage & Queueing
- Log inbound requests to `inbound_log.json` for audit.
- (Future) Push to Redis or message queue for worker processing.
