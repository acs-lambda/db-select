import json
import boto3
from typing import Dict, Any, Union, Optional
from botocore.exceptions import ClientError
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
lambda_client = boto3.client('lambda')
dynamodb = boto3.resource('dynamodb')
sessions_table = dynamodb.Table('Sessions')

class AuthorizationError(Exception):
    """Custom exception for authorization failures"""
    pass

def invoke(function_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Invoke a Lambda function by name with the given payload
    
    Args:
        function_name (str): Name of the Lambda function to invoke
        payload (Dict[str, Any]): Payload to send to the Lambda function
        
    Returns:
        Dict[str, Any]: Response from the Lambda function
        
    Raises:
        ClientError: If Lambda invocation fails
    """
    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(payload)
        )
        
        # Parse the response payload
        response_payload = json.loads(response['Payload'].read().decode('utf-8'))
        
        # If the Lambda function returned an error
        if 'FunctionError' in response:
            logger.error(f"Lambda function {function_name} returned an error: {response_payload}")
            raise ClientError(
                error_response={'Error': {'Message': response_payload.get('errorMessage', 'Unknown error')}},
                operation_name='InvokeLambda'
            )
            
        return response_payload
        
    except ClientError as e:
        logger.error(f"Failed to invoke Lambda function {function_name}: {str(e)}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Lambda response for {function_name}: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error invoking Lambda function {function_name}: {str(e)}")
        raise

def parse_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse an event from either API Gateway or direct Lambda invocation
    
    Args:
        event (Dict[str, Any]): The event to parse, either from API Gateway or direct Lambda
        
    Returns:
        Dict[str, Any]: Parsed event data including body and cookies if present
        
    Example API Gateway event:
    {
        "body": "{\"key\": \"value\"}",
        "headers": {
            "Cookie": "session=abc123"
        }
    }
    
    Example direct Lambda event:
    {
        "key": "value",
        "session": "abc123"
    }
    """
    try:
        parsed_data = {}
        
        # Check if this is an API Gateway event
        if 'body' in event:
            # Parse the body if it's a string
            if isinstance(event['body'], str):
                try:
                    parsed_data.update(json.loads(event['body']))
                except json.JSONDecodeError:
                    # If body is not JSON, use it as is
                    parsed_data['body'] = event['body']
            else:
                parsed_data.update(event['body'])
                
            # Handle cookies from API Gateway
            if 'headers' in event and 'Cookie' in event['headers']:
                cookies = event['headers']['Cookie']
                # Parse cookies into a dictionary
                cookie_dict = dict(
                    cookie.split('=', 1) for cookie in cookies.split('; ')
                )
                parsed_data.update(cookie_dict)
                
        else:
            # Direct Lambda invocation - use event as is
            parsed_data.update(event)
            
        return parsed_data
        
    except Exception as e:
        logger.error(f"Error parsing event: {str(e)}")
        raise

def authorize(user_id: str, session_id: str) -> None:
    """
    Authorize a user by validating their session
    
    Args:
        user_id (str): The user ID to validate
        session_id (str): The session ID to validate
        
    Returns:
        None
        
    Raises:
        AuthorizationError: If authorization fails
    """
    try:
        if not session_id:
            raise AuthorizationError("No session ID provided")
            
        # Query the Sessions table
        response = sessions_table.get_item(
            Key={'session_id': session_id}
        )
        
        session = response.get('Item')
        if not session:
            logger.warning(f"Session not found: {session_id}")
            raise AuthorizationError("ACS: Unauthorized")
            
        # Validate user_id matches session
        if session.get('associated_account') != user_id:
            logger.warning(f"User ID mismatch: {user_id} != {session.get('associated_account')}")
            raise AuthorizationError("ACS: Unauthorized")
                            
    except ClientError as e:
        logger.error(f"DynamoDB error during authorization: {str(e)}")
        raise AuthorizationError("ACS: Unauthorized")
    except Exception as e:
        logger.error(f"Unexpected error during authorization: {str(e)}")
        raise AuthorizationError("ACS: Unauthorized") 