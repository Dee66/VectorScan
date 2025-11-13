# Lead Capture Endpoint Example

This document shows two minimal approaches to implement the `LEAD_CAPTURE_ENDPOINT` used by VectorScan's optional lead capture feature.

VectorScan POST payload structure (JSON):
```json
{
  "email": "user@example.com",
  "status": "PASS",
  "file": "path/to/tfplan.json",
  "violations": [],
  "counts": {"violations": 0},
  "checks": ["P-SEC-001", "P-FIN-001"]
}
```

## 1. Flask Microservice (Container or VM)

```python
from flask import Flask, request, jsonify
import re

app = Flask(__name__)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

@app.post('/capture')
def capture():
    data = request.get_json(force=True, silent=True) or {}
    email = data.get('email')
    if not email or not EMAIL_RE.match(email):
        return jsonify({'error': 'invalid email'}), 400
    # TODO: persist to database / CRM / email marketing tool
    # Example logging only:
    app.logger.info('LeadCapture: %s status=%s violations=%d', email, data.get('status'), len(data.get('violations', [])))
    return jsonify({'ok': True}), 202

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

Run locally:
```bash
pip install flask
python lead_capture.py
```

Configure VectorScan:
```bash
LEAD_CAPTURE_ENABLED=1 \
LEAD_CAPTURE_ENDPOINT="http://localhost:8080/capture" \
python3 VectorGuard/tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-pass.json --json --lead-capture-email you@company.com
```

## 2. Serverless (AWS Lambda + API Gateway) Outline

Handler (Python):
```python
import json, re
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def handler(event, context):
    try:
        body = json.loads(event.get('body') or '{}')
    except json.JSONDecodeError:
        return {'statusCode': 400, 'body': json.dumps({'error': 'invalid json'})}
    email = body.get('email')
    if not email or not EMAIL_RE.match(email):
        return {'statusCode': 400, 'body': json.dumps({'error': 'invalid email'})}
    # TODO: persist to DynamoDB or forward to SNS/SQS for async processing
    print(f"LeadCapture: {email} status={body.get('status')} violations={len(body.get('violations', []))}")
    return {'statusCode': 202, 'body': json.dumps({'ok': True})}
```

Terraform snippet (conceptual skeleton):
```hcl
resource "aws_lambda_function" "lead_capture" {
  function_name = "lead-capture"
  handler       = "handler.handler"
  runtime       = "python3.11"
  filename      = "build.zip" # zipped handler
  source_code_hash = filebase64sha256("build.zip")
  role          = aws_iam_role.lead_capture_role.arn
}

resource "aws_apigatewayv2_api" "http" { name = "lead-capture" protocol_type = "HTTP" }
resource "aws_apigatewayv2_integration" "lambda" {
  api_id           = aws_apigatewayv2_api.http.id
  integration_type = "AWS_PROXY"
  integration_uri  = aws_lambda_function.lead_capture.invoke_arn
}
resource "aws_apigatewayv2_route" "capture" { api_id = aws_apigatewayv2_api.http.id route_key = "POST /capture" target = "integrations/${aws_apigatewayv2_integration.lambda.id}" }
resource "aws_apigatewayv2_stage" "prod" { api_id = aws_apigatewayv2_api.http.id name = "$default" auto_deploy = true }

output "lead_capture_endpoint" {
  value = aws_apigatewayv2_api.http.api_endpoint
}
```

Invoke VectorScan using the output endpoint:
```bash
LEAD_CAPTURE_ENABLED=1 \
LEAD_CAPTURE_ENDPOINT="https://YOUR_ID.execute-api.REGION.amazonaws.com/capture" \
python3 VectorGuard/tools/vectorscan/vectorscan.py examples/aws-pgvector-rag/tfplan-pass.json --json --lead-capture-email you@company.com
```

## Security Considerations
- Rate-limit requests (API Gateway throttling or CloudFront + WAF) to prevent abuse.
- Validate and sanitize inputs to avoid injection.
- Persist only necessary fields; avoid storing raw tfplan paths if sensitive.
- Consider a double opt-in workflow for marketing emails.

## Minimal cURL Test
```bash
curl -X POST "$LEAD_CAPTURE_ENDPOINT" \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","status":"PASS","violations":[],"counts":{"violations":0},"checks":["P-SEC-001","P-FIN-001"]}'
```

## Next Steps
- Add persistence (DynamoDB/Postgres) and analytics tagging.
- Wire into email marketing automation (e.g., SES → Segment → marketing tool).
- Implement retry or async queue for resiliency if desired.
