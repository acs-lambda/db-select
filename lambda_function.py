import os
import json
import boto3
from boto3.dynamodb.conditions import Key

# reuse clients
dynamodb      = boto3.resource('dynamodb')
lambda_client = boto3.client('lambda')

def fetch_cors_headers():
    """
    Invoke the designated CORS Lambda and extract its 'headers' map.
    Falls back to empty dict on error.
    """
    fn = 'Allow-Cors'

    try:
        resp = lambda_client.invoke(
            FunctionName=fn,
            InvocationType='RequestResponse',
            Payload=json.dumps({}).encode('utf-8')
        )
        # read and parse its JSON response
        payload = resp['Payload'].read().decode('utf-8')
        result  = json.loads(payload)
        return result.get('headers', {})
    except Exception:
        return {}

def lambda_handler(event, context):
    cors_headers = fetch_cors_headers()

    # CORS preflight
    if event.get('httpMethod') == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': cors_headers
        }

    # parse body (API Gateway proxy vs direct invoke)
    body = event.get('body')
    if body:
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return {
                'statusCode': 400,
                'headers': cors_headers,
                'body': json.dumps({'error': 'Invalid JSON in body'})
            }
    else:
        payload = event
    print(payload)

    table_name = payload.get('table_name')
    index_name  = payload.get('index_name')
    key_name    = payload.get('key_name')
    key_value   = payload.get('key_value')
    if not all([table_name, index_name, key_name, key_value]):
        return {
            'statusCode': 400,
            'headers': cors_headers,
            'body': json.dumps({
            'error': 'Missing one of table_name, index_name, key_name, or key_value'
        })
    }

    table = dynamodb.Table(table_name)
    try:
        response = table.query(
            IndexName=index_name,
            KeyConditionExpression=Key(key_name).eq(key_value)
        )
        items = response.get('Items', [])
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps(items)
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({'error': str(e)})
        }
