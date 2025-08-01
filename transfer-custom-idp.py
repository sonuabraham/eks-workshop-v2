import json
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configure your specific users/groups that should use SSH keys
SSH_KEY_USERS = {
    'admin-user': {
        'public_key': 'ssh-rsa AAAAB3NzaC1yc2E... your-public-key-here',
        'role': 'arn:aws:iam::ACCOUNT:role/TransferRole',
        'home_directory': '/bucket-name/admin-user/',
        'policy': None  # Optional: restrict access with IAM policy
    },
    'service-account': {
        'public_key': 'ssh-rsa AAAAB3NzaC1yc2E... another-public-key-here',
        'role': 'arn:aws:iam::ACCOUNT:role/TransferServiceRole',
        'home_directory': '/bucket-name/service-account/',
        'policy': None
    }
}

# Directory Service configuration
DIRECTORY_SERVICE_ID = 'your-directory-service-id'
ds_client = boto3.client('ds')

def lambda_handler(event, context):
    """
    Custom identity provider for AWS Transfer Family
    Routes SSH key users vs Directory Service users
    """
    
    try:
        # Extract authentication details
        username = event.get('username', '')
        password = event.get('password', '')
        protocol = event.get('protocol', '')
        source_ip = event.get('sourceIp', '')
        
        logger.info(f"Authentication attempt for user: {username} from IP: {source_ip}")
        
        # Check if user should use SSH key authentication
        if username in SSH_KEY_USERS:
            return handle_ssh_key_auth(username, event)
        
        # Fall back to Directory Service authentication
        return handle_directory_service_auth(username, password, event)
        
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        return {
            'Response': json.dumps({})  # Empty response denies access
        }

def handle_ssh_key_auth(username, event):
    """Handle SSH key-based authentication"""
    
    user_config = SSH_KEY_USERS[username]
    
    # For SSH key auth, we return the user configuration
    # The actual key validation happens at the Transfer Family level
    response = {
        'Role': user_config['role'],
        'HomeDirectory': user_config['home_directory'],
        'PublicKeys': [user_config['public_key']]
    }
    
    # Add policy if specified
    if user_config.get('policy'):
        response['Policy'] = user_config['policy']
    
    logger.info(f"SSH key authentication configured for user: {username}")
    
    return {
        'Response': json.dumps(response)
    }

def handle_directory_service_auth(username, password, event):
    """Handle Directory Service authentication"""
    
    if not password:
        logger.info(f"No password provided for directory service user: {username}")
        return {'Response': json.dumps({})}
    
    try:
        # Authenticate against Directory Service
        response = ds_client.authenticate_user(
            DirectoryId=DIRECTORY_SERVICE_ID,
            UserName=username,
            Password=password
        )
        
        if response.get('AuthenticationResult'):
            # Get user details from directory
            user_details = get_directory_user_details(username)
            
            # Configure Transfer Family response
            transfer_response = {
                'Role': 'arn:aws:iam::ACCOUNT:role/TransferDirectoryRole',
                'HomeDirectory': f'/bucket-name/{username}/',
                'HomeDirectoryType': 'LOGICAL',
                'HomeDirectoryMappings': [
                    {
                        'Entry': '/',
                        'Target': f'/bucket-name/{username}'
                    }
                ]
            }
            
            logger.info(f"Directory Service authentication successful for user: {username}")
            return {
                'Response': json.dumps(transfer_response)
            }
        else:
            logger.info(f"Directory Service authentication failed for user: {username}")
            return {'Response': json.dumps({})}
            
    except Exception as e:
        logger.error(f"Directory Service authentication error for {username}: {str(e)}")
        return {'Response': json.dumps({})}

def get_directory_user_details(username):
    """Get additional user details from Directory Service if needed"""
    try:
        # You can extend this to get group memberships, attributes, etc.
        response = ds_client.describe_users(
            DirectoryId=DIRECTORY_SERVICE_ID,
            UserNames=[username]
        )
        return response.get('Users', [])
    except Exception as e:
        logger.error(f"Error getting directory user details: {str(e)}")
        return []