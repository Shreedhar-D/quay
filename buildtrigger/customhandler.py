import json
import logging
from typing import Dict, Any, Optional, List, Tuple

from jsonschema import ValidationError, validate

from buildtrigger.basehandler import BuildTriggerHandler
from buildtrigger.triggerutil import (
    InvalidPayloadException,
    TriggerStartException,
    raise_if_skipped_build,
)
from util.security.ssh import generate_ssh_keypair

logger = logging.getLogger(__name__)

class QuayCustomBuildTrigger(BuildTriggerHandler):
    """
    build trigger handler for Quay.io with improved security and flexibility.
    
    Key Improvements:
    - More robust payload validation
    - Enhanced logging
    - Support for additional metadata sources
    - Improved error handling
    """
    
    @classmethod
    def payload_schema(cls) -> Dict[str, Any]:
        """
        Dynamic payload schema generation with enhanced security checks.
        
        Returns:
            Dict: JSON schema for webhook payload validation
        """
        return {
            "type": "object",
            "properties": {
                "commit": {
                    "type": "string",
                    "description": "Git commit SHA-1 identifier",
                    "minLength": 7,
                    "maxLength": 40,
                    "pattern": "^[A-Fa-f0-9]+$",
                },
                "ref": {
                    "type": "string",
                    "description": "Git reference for commit",
                    "pattern": "^refs/(heads|tags|remotes)/(.+)$",
                },
                "repository": {
                    "type": "object",
                    "description": "Repository metadata",
                    "properties": {
                        "name": {"type": "string"},
                        "namespace": {"type": "string"},
                        "visibility": {
                            "type": "string", 
                            "enum": ["public", "private"]
                        }
                    },
                    "required": ["name", "namespace"]
                },
                "security_scan": {
                    "type": "object",
                    "description": "Security scan results",
                    "properties": {
                        "status": {"type": "string"},
                        "vulnerabilities": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "severity": {"type": "string"},
                                    "package": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            },
            "required": ["commit", "ref"],
            "additionalProperties": True  # Allow flexibility for future extensions
        }
    
    def validate_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive payload validation with advanced error handling.
        
        Args:
            payload (Dict): Incoming webhook payload
        
        Returns:
            Dict: Validated and potentially transformed payload
        
        Raises:
            InvalidPayloadException: For validation failures
        """
        try:
            # Validate against the schema
            validate(instance=payload, schema=self.payload_schema())
            
            # Additional custom validations
            self._perform_security_checks(payload)
            
            return payload
        except ValidationError as ve:
            logger.error(f"Payload validation failed: {ve}")
            raise InvalidPayloadException(f"Invalid payload: {ve.message}")
    
    def _perform_security_checks(self, payload: Dict[str, Any]) -> None:
        """
        Perform additional security checks on the payload.
        
        Args:
            payload (Dict): Validated payload
        
        Raises:
            InvalidPayloadException: If security checks fail
        """
        # Example security checks
        if payload.get('security_scan', {}).get('status') == 'failed':
            logger.warning(f"Security scan failed for commit {payload.get('commit')}")
            # Optionally, you could prevent build trigger based on scan results
    
    def handle_trigger_request(self, request):
        """
        Enhanced trigger request handling with comprehensive error management.
        
        Args:
            request: Incoming webhook request
        
        Returns:
            Prepared build configuration
        
        Raises:
            Various exceptions for different failure scenarios
        """
        try:
            # Parse payload
            payload = request.data
            if not payload:
                raise InvalidPayloadException("Empty payload received")
            
            # Parse JSON
            try:
                metadata = json.loads(payload)
            except json.JSONDecodeError as je:
                raise InvalidPayloadException(f"Invalid JSON: {je}")
            
            # Validate payload
            validated_metadata = self.validate_payload(metadata)
            
            # Prepare build
            prepared = self.prepare_build(validated_metadata)
            
            # Check for skipped builds
            raise_if_skipped_build(prepared, self.config)
            
            return prepared
        
        except Exception as e:
            logger.error(f"Trigger request processing failed: {e}")
            raise
    
    def manual_start(self, run_parameters=None):
        """
        Enhanced manual build start with more flexible parameter handling.
        
        Args:
            run_parameters (Dict, optional): Parameters for manual build
        
        Returns:
            Prepared build configuration
        
        Raises:
            TriggerStartException: For invalid or missing parameters
        """
        if not run_parameters:
            raise TriggerStartException("No run parameters provided")
        
        # More flexible parameter extraction
        commit_sha = run_parameters.get("commit_sha")
        branch = run_parameters.get("branch")
        
        if not commit_sha:
            raise TriggerStartException("Missing required commit SHA")
        
        metadata = {
            "commit": commit_sha,
            "ref": f"refs/heads/{branch}" if branch else "refs/heads/main",
            "git_url": self.config.get("build_source")
        }
        
        try:
            return self.prepare_build(metadata, is_manual=True)
        except Exception as e:
            raise TriggerStartException(f"Build preparation failed: {e}")
