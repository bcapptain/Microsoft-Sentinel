import azure.functions as func
import logging
import json
import gzip
#import io
import os
import base64
import hashlib
import datetime
import hmac
import requests

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="datadogforwarder")
def datadogforwarder(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    try:
        # Check if the request is gzip-compressed
        if req.headers.get('Content-Encoding') == 'gzip':
            # Decompress the request body
            decompressed_data = gzip.decompress(req.get_body())
            #logging.info(decompressed_data)
            # Convert the decompressed data to JSON
            req_body = json.loads(decompressed_data)
        else:
            req_body = req.get_json()
    except ValueError:
        return func.HttpResponse(
             "Invalid JSON format in request body.",
             status_code=400
        )
    #logging.info(req_body)

   # Remove "attributes" Object, since it blows up the LA table over time
    if isinstance(req_body, list):
        for item in req_body:
            if "attributes" in item:
                del item["attributes"]  # Remove the "attributes" object
                #logging.info("Removed the attributes object!")
    elif isinstance(req_body, dict):
        if "attributes" in req_body:
            del req_body["attributes"]  # Remove the "attributes" object
            #logging.info("Removed the attributes object!")
    
    # Convert the request body to JSON string
    data = json.dumps(req_body)
    
    #Debug Output
    logging.info(f"Data received: {data}") 
    
    # Log Analytics workspace details
    try:
        workspace_id = os.environ['LOG_ANALYTICS_WORKSPACE_ID']
    except KeyError:
        logging.error("Environment variable 'LOG_ANALYTICS_WORKSPACE_ID' not found.")
        workspace_id = None
    try:
        shared_key = os.environ['LOG_ANALYTICS_PRIMARY_KEY']
    except KeyError:
        logging.error("Environment variable 'LOG_ANALYTICS_PRIMARY_KEY' not found.")
        shared_key = None
    log_type = 'NGINX'
    timestamp = datetime.datetime.now().isoformat()
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")
    json_data = data
    #logging.info(f"Worspace ID: {workspace_id}")
    #logging.info(f"Shared Key: {shared_key}")
    #logging.info(f"Table: {log_type}")
    #logging.info(f"JSON DATA: {json_data}")
    
    # Build the API signature
    string_to_hash = 'POST\n{}\napplication/json\nx-ms-date:{}\n/api/logs'.format(len(json_data), timestamp)
    hashed_string = base64.b64encode(hmac.new(base64.b64decode(shared_key), msg=string_to_hash.encode('utf-8'), digestmod=hashlib.sha256).digest()).decode()
    signature = "SharedKey {}:{}".format(workspace_id, hashed_string)
    # Build and send the request
    headers = {
        'content-type': 'application/json',
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': timestamp
    }
    response = requests.post("https://{}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01".format(workspace_id), data=json_data, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        logging.info('Log data sent successfully. Response code: {}'.format(response.status_code))
    else:
        logging.error('Log data was not sent. Response : {}'.format(response.content))
    return func.HttpResponse(status_code=200)