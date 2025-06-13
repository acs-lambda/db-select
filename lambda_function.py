import os
import json
import boto3
import logging
import time
from decimal import Decimal
from boto3.dynamodb.conditions import Key

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Custom JSON encoder to handle Decimal types
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)

# Helper function to safely serialize objects with Decimal types
def safe_json_dumps(obj):
    return json.dumps(obj, cls=DecimalEncoder)

# reuse clients
dynamodb      = boto3.resource('dynamodb')
lambda_client = boto3.client('lambda')

def fetch_cors_headers():
    """
    Invoke the designated CORS Lambda and extract its 'headers' map.
    Falls back to empty dict on error.
    """
    fn = 'Allow-Cors'
    logger.info(f"Fetching CORS headers from Lambda function: {fn}")

    try:
        logger.debug("Invoking CORS Lambda function")
        resp = lambda_client.invoke(
            FunctionName=fn,
            InvocationType='RequestResponse',
            Payload=json.dumps({}).encode('utf-8')
        )
        # read and parse its JSON response
        payload = resp['Payload'].read().decode('utf-8')
        result  = json.loads(payload)
        headers = result.get('headers', {})
        logger.info("Successfully retrieved CORS headers")
        return headers
    except Exception as e:
        logger.error(f"Failed to fetch CORS headers: {str(e)}", exc_info=True)
        return {}

def check_rate_limit(account_id):
    """
    Check if the account has exceeded their AWS API rate limit.
    Returns (is_rate_limited, current_invocations, rate_limit)
    """
    try:
        # First check the user's rate limit from Users table
        users_table = dynamodb.Table('Users')
        user_response = users_table.get_item(
            Key={'account_id': account_id}
        )
        user_item = user_response.get('Item', {})
        rate_limit = user_item.get('rl_aws', 0)  # Default to 0 if not set
        
        # Check current invocations in RL_AWS table
        rl_table = dynamodb.Table('RL_AWS')
        try:
            rl_response = rl_table.get_item(
                Key={'associated_account': account_id}
            )
            current_invocations = rl_response.get('Item', {}).get('invocations', 0)
        except Exception:
            current_invocations = 0
            
        return current_invocations >= rate_limit, current_invocations, rate_limit
    except Exception as e:
        logger.error(f"Error checking rate limit: {str(e)}", exc_info=True)
        return False, 0, 0

def update_rate_limit(account_id):
    """
    Update the rate limit counter for the account.
    Creates new record with TTL if doesn't exist.
    """
    try:
        rl_table = dynamodb.Table('RL_AWS')
        current_time = int(time.time() * 1000)  # Current time in milliseconds
        ttl_time = current_time + (60 * 1000)  # 1 minute from now
        
        # Try to update existing record
        try:
            response = rl_table.update_item(
                Key={'associated_account': account_id},
                UpdateExpression='SET invocations = invocations + :inc, ttl = :ttl',
                ExpressionAttributeValues={
                    ':inc': 1,
                    ':ttl': ttl_time
                },
                ReturnValues='UPDATED_NEW'
            )
        except rl_table.meta.client.exceptions.ResourceNotFoundException:
            # Create new record if doesn't exist
            rl_table.put_item(
                Item={
                    'associated_account': account_id,
                    'invocations': 1,
                    'ttl': ttl_time
                }
            )
    except Exception as e:
        logger.error(f"Error updating rate limit: {str(e)}", exc_info=True)

def lambda_handler(event, context):
    logger.info("Lambda function started")
    logger.debug(f"Received event: {safe_json_dumps(event)}")
    
    cors_headers = fetch_cors_headers()
    logger.debug(f"CORS headers: {safe_json_dumps(cors_headers)}")

    # CORS preflight
    if event.get('httpMethod') == 'OPTIONS':
        logger.info("Handling OPTIONS request (CORS preflight)")
        return {
            'statusCode': 200,
            'headers': cors_headers
        }

    # Get account ID from the request
    account_id = event.get('requestContext', {}).get('authorizer', {}).get('claims', {}).get('sub')
    if not account_id:
        logger.error("No account ID found in request")
        return {
            'statusCode': 401,
            'headers': cors_headers,
            'body': safe_json_dumps({'error': 'Unauthorized - No account ID'})
        }

    # Check rate limit
    is_rate_limited, current_invocations, rate_limit = check_rate_limit(account_id)
    if is_rate_limited:
        logger.warning(f"Rate limit exceeded for account {account_id}. Current: {current_invocations}, Limit: {rate_limit}")
        return {
            'statusCode': 429,
            'headers': cors_headers,
            'body': safe_json_dumps({
                'error': 'Rate limit exceeded',
                'message': f'You have exceeded your AWS API rate limit of {rate_limit} requests per minute. Please try again later.'
            })
        }

    # parse body (API Gateway proxy vs direct invoke)
    body = event.get('body')
    if body:
        logger.debug("Attempting to parse request body")
        try:
            payload = json.loads(body)
            logger.info("Successfully parsed request body")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON body: {str(e)}")
            return {
                'statusCode': 400,
                'headers': cors_headers,
                'body': safe_json_dumps({'error': 'Invalid JSON in body'})
            }
    else:
        logger.info("No body found, using event as payload")
        payload = event
    
    logger.debug(f"Processed payload: {safe_json_dumps(payload)}")

    # Validate required parameters
    table_name = payload.get('table_name')
    index_name = payload.get('index_name')
    key_name   = payload.get('key_name')
    key_value  = payload.get('key_value')
    
    logger.info(f"Validating parameters - Table: {table_name}, Index: {index_name}, Key: {key_name}")
    
    if not all([table_name, index_name, key_name, key_value]):
        missing_params = [param for param, value in [
            ('table_name', table_name),
            ('index_name', index_name),
            ('key_name', key_name),
            ('key_value', key_value)
        ] if not value]
        logger.error(f"Missing required parameters: {', '.join(missing_params)}")
        return {
            'statusCode': 400,
            'headers': cors_headers,
            'body': safe_json_dumps({
                'error': 'Missing one of table_name, index_name, key_name, or key_value'
            })
        }

    logger.info(f"Querying DynamoDB table {table_name} using index {index_name}")
    table = dynamodb.Table(table_name)
    try:
        logger.debug(f"Executing query with key condition: {key_name} = {key_value}")
        response = table.query(
            IndexName=index_name,
            KeyConditionExpression=Key(key_name).eq(key_value)
        )
        items = response.get('Items', [])
        logger.info(f"Query successful. Retrieved {len(items)} items")
        logger.debug(f"Query response: {safe_json_dumps(items)}")
        
        # Update rate limit counter after successful execution
        update_rate_limit(account_id)
        
        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': safe_json_dumps(items)
        }

    except Exception as e:
        logger.error(f"DynamoDB query failed: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': safe_json_dumps({'error': str(e)})
        }
    finally:
        logger.info("Lambda function execution completed")
