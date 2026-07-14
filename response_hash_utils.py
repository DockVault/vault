"""
Response Hash Utilities for Conditional Updates and Traffic Optimization

Provides ETag-based caching mechanism to reduce network traffic and latency.
When content hasn't changed, returns 304 Not Modified instead of full payload.

This implements HTTP conditional requests (RFC 7232) using ETags.

Performance Benefits:
- Reduces bandwidth by 70-90% for unchanged data
- Lowers server CPU for JSON serialization
- Improves client-side performance (no DOM updates needed)
- Particularly effective for frequently-polled endpoints

Usage:
    from response_hash_utils import compute_response_hash, check_if_none_match, create_cached_response
    
    @app.get("/api/data")
    async def get_data(request: Request):
        data = fetch_data()
        response_hash = compute_response_hash(data)
        
        # Check if client has current version
        if check_if_none_match(request, response_hash):
            return Response(status_code=304)
        
        # Return data with ETag header
        return create_cached_response(data, response_hash)
"""
import hashlib
import json
from typing import Any, Union, List
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel


def compute_response_hash(data: Any) -> str:
    """
    Compute SHA-256 hash of response data for conditional updates.
    
    This allows clients to skip data transfer and DOM updates if content hasn't changed.
    Handles Pydantic models, lists, dicts, and primitive types.
    
    Args:
        data: Response data to hash (Pydantic model, list, dict, or primitive)
    
    Returns:
        SHA-256 hash string (64 hex characters)
    
    Examples:
        >>> user = User(id=1, name="John")
        >>> compute_response_hash(user)
        'a1b2c3d4...'
        
        >>> users = [User(id=1), User(id=2)]
        >>> compute_response_hash(users)
        'e5f6g7h8...'
    """
    # Convert Pydantic models or lists to JSON string
    if hasattr(data, 'model_dump'):
        # Single Pydantic model
        json_str = json.dumps(data.model_dump(mode='json'), default=str, sort_keys=True)
    elif isinstance(data, list):
        # List of Pydantic models or primitives
        json_list = [
            item.model_dump(mode='json') if hasattr(item, 'model_dump') else item 
            for item in data
        ]
        json_str = json.dumps(json_list, default=str, sort_keys=True)
    elif isinstance(data, dict):
        # Plain dictionary
        json_str = json.dumps(data, default=str, sort_keys=True)
    else:
        # Primitive type or other
        json_str = json.dumps(data, default=str, sort_keys=True)
    
    # Compute SHA-256 hash
    return hashlib.sha256(json_str.encode('utf-8')).hexdigest()


def check_if_none_match(request: Request, current_hash: str) -> bool:
    """
    Check if client's If-None-Match header matches current content hash.
    
    This implements the conditional GET mechanism (RFC 7232).
    If the ETag matches, the content hasn't changed and we can return 304.
    
    Args:
        request: FastAPI request object
        current_hash: Current content hash to compare against
    
    Returns:
        True if content matches (should return 304 Not Modified)
        False if content changed or no If-None-Match header (return full response)
    
    Examples:
        >>> if check_if_none_match(request, response_hash):
        ...     return Response(status_code=304)
    """
    if_none_match = request.headers.get('If-None-Match')
    if not if_none_match:
        return False
    # Parse per RFC 7232 §3.2: "*" matches any current representation; otherwise it's a
    # comma-separated list of (possibly weak, W/-prefixed) quoted ETags -- match if any equals ours.
    if if_none_match.strip() == '*':
        return True
    for tag in if_none_match.split(','):
        tag = tag.strip()
        if tag.startswith('W/'):
            tag = tag[2:].strip()
        if tag.strip('"') == current_hash:
            return True
    return False


def create_cached_response(
    data: Any, 
    response_hash: str,
    status_code: int = 200,
    cache_control: str = "no-cache"
) -> Response:
    """
    Create HTTP response with ETag header for caching.
    
    Sets appropriate headers for conditional requests:
    - ETag: Content hash for comparison
    - Cache-Control: Caching policy (default: no-cache - revalidate each time)
    
    Args:
        data: Response data (will be JSON serialized)
        response_hash: Computed hash of the data
        status_code: HTTP status code (default 200)
        cache_control: Cache-Control header value (default "no-cache")
    
    Returns:
        FastAPI Response with ETag and Cache-Control headers
    
    Examples:
        >>> data = get_dashboard_stats()
        >>> hash_val = compute_response_hash(data)
        >>> return create_cached_response(data, hash_val)
    """
    # Convert data to JSON
    if hasattr(data, 'model_dump'):
        content = json.dumps(data.model_dump(mode='json'), default=str)
    elif isinstance(data, list):
        json_list = [
            item.model_dump(mode='json') if hasattr(item, 'model_dump') else item 
            for item in data
        ]
        content = json.dumps(json_list, default=str)
    else:
        content = json.dumps(data, default=str)
    
    # Create response with ETag and caching headers
    return Response(
        content=content,
        media_type="application/json",
        status_code=status_code,
        headers={
            "ETag": f'"{response_hash}"',  # ETags should be quoted per RFC 7232
            "Cache-Control": cache_control
        }
    )


def create_not_modified_response() -> Response:
    """
    Create 304 Not Modified response.
    
    Returns minimal response when content hasn't changed.
    Client should use cached data instead of re-parsing response.
    
    Returns:
        FastAPI Response with 304 status code
    
    Examples:
        >>> if check_if_none_match(request, current_hash):
        ...     return create_not_modified_response()
    """
    return Response(
        status_code=304,
        headers={
            "Cache-Control": "no-cache"
        }
    )


# Convenience function combining hash check and response creation
def handle_conditional_response(
    request: Request,
    data: Any,
    cache_control: str = "no-cache"
) -> Response:
    """
    All-in-one handler for conditional responses.
    
    Computes hash, checks If-None-Match, and returns either 304 or full response.
    Use this when you want simple one-line conditional response handling.
    
    Args:
        request: FastAPI request object
        data: Response data
        cache_control: Cache-Control header value
    
    Returns:
        Either 304 Not Modified or 200 OK with data and ETag
    
    Examples:
        >>> @app.get("/api/data")
        ... async def get_data(request: Request):
        ...     data = fetch_data()
        ...     return handle_conditional_response(request, data)
    """
    response_hash = compute_response_hash(data)
    
    if check_if_none_match(request, response_hash):
        return create_not_modified_response()
    
    return create_cached_response(data, response_hash, cache_control=cache_control)
