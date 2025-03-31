import logging
import azure.functions as func
import json
import datetime
from datetime import UTC
import os
import requests
import base64
import hashlib
import hmac

app = func.FunctionApp()

def clean_field_name(key: str) -> str:
    """Remove '_' prefix from any field name."""
    if key.startswith('_'):
        return key[1:]
    return key

def build_signature(workspace_id, workspace_key, date, content_length, method, content_type, resource):
    """Build the signature for Log Analytics authentication."""
    x_headers = 'x-ms-date:' + date
    string_to_sign = method + '\n' + str(content_length) + '\n' + content_type + '\n' + x_headers + '\n' + resource
    bytes_to_sign = string_to_sign.encode('utf-8')
    decoded_key = base64.b64decode(workspace_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_sign, digestmod=hashlib.sha256).digest()
    ).decode('utf-8')
    return f"SharedKey {workspace_id}:{encoded_hash}"

@app.route(route="GELFReceiver", auth_level=func.AuthLevel.FUNCTION)
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    try:
        # Get the request body
        req_body = req.get_json()
        
        if not req_body:
            return func.HttpResponse(
                "No data received",
                status_code=400
            )

        # Get Log Analytics workspace details
        workspace_id = os.environ["LogAnalyticsWorkspaceId"]
        workspace_key = os.environ["LogAnalyticsWorkspaceKey"]
        table_name = os.environ.get("LogAnalyticsTableName", "GELF_TEST_CL")

        # Process GELF data
        if isinstance(req_body, list):
            gelf_entries = req_body
        else:
            gelf_entries = [req_body]

        # Prepare data for Log Analytics
        records = []
        for entry in gelf_entries:
            # Clean field names
            cleaned_entry = {clean_field_name(k): v for k, v in entry.items()}
            
            if 'gl2_receive_timestamp' in cleaned_entry:
                try:
                    # Try to parse the string timestamp first
                    timestamp = datetime.datetime.strptime(cleaned_entry['gl2_receive_timestamp'], '%Y-%m-%d %H:%M:%S.%f')
                except (ValueError, TypeError):
                    try:
                        # Fall back to original timestamp if available
                        timestamp = datetime.datetime.fromtimestamp(float(cleaned_entry['timestamp']), UTC)
                    except (ValueError, TypeError, KeyError):
                        timestamp = datetime.datetime.now(UTC)
                cleaned_entry['TimeGenerated'] = timestamp.isoformat()
            else:
                cleaned_entry['TimeGenerated'] = datetime.datetime.now(UTC).isoformat()

            for key, value in cleaned_entry.items():
                if not isinstance(value, (str, int, float, bool)):
                    cleaned_entry[key] = str(value)

            records.append(cleaned_entry)

        # Prepare request for Log Analytics
        body = json.dumps(records)
        method = 'POST'
        content_type = 'application/json'
        resource = '/api/logs'
        rfc1123date = datetime.datetime.now(UTC).strftime('%a, %d %b %Y %H:%M:%S GMT')
        content_length = len(body)
        
        # Build signature
        signature = build_signature(
            workspace_id,
            workspace_key,
            rfc1123date,
            content_length,
            method,
            content_type,
            resource
        )

        # Set headers
        headers = {
            'Content-Type': content_type,
            'Authorization': signature,
            'Log-Type': table_name,
            'x-ms-date': rfc1123date
        }

        # Send data to Log Analytics
        uri = f'https://{workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01'
        response = requests.post(uri, data=body, headers=headers)
        
        if response.status_code >= 200 and response.status_code <= 299:
            return func.HttpResponse(
                json.dumps({"status": "success", "processed_records": len(records)}),
                mimetype="application/json",
                status_code=200
            )
        else:
            raise Exception(f"Request failed: {response.status_code}, {response.text}")

    except Exception as e:
        logging.error(f"Error processing GELF data: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            mimetype="application/json",
            status_code=500
        )