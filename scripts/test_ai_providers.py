#!/usr/bin/env python3
"""
AI Provider Connection Test Script

Tests all configured AI providers to verify API keys, endpoints, and connectivity.
Usage: python test_ai_providers.py
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import requests
from typing import Dict, Tuple

# Load .env from current directory
env_path = Path(__file__).parent / '.env'
load_dotenv(env_path)

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(text: str):
    """Print a formatted header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(70)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.END}\n")

def print_success(text: str):
    """Print success message"""
    print(f"{Colors.GREEN}✓ {text}{Colors.END}")

def print_error(text: str):
    """Print error message"""
    print(f"{Colors.RED}✗ {text}{Colors.END}")

def print_warning(text: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.END}")

def print_info(text: str):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ {text}{Colors.END}")

def test_openai() -> Tuple[bool, str]:
    """Test OpenAI API connection"""
    api_key = os.getenv('OPENAI_API_KEY')
    model = os.getenv('OPENAI_MODEL', 'gpt-3.5-turbo')
    
    if not api_key:
        return False, "No API key configured"
    
    if not api_key.startswith('sk-'):
        return False, f"Invalid API key format (should start with 'sk-')"
    
    try:
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        
        # Test with a minimal completion request
        payload = {
            'model': model,
            'messages': [{'role': 'user', 'content': 'Hi'}],
            'max_tokens': 5
        }
        
        response = requests.post(
            'https://api.openai.com/v1/chat/completions',
            headers=headers,
            json=payload,
            timeout=10
        )
        
        if response.status_code == 200:
            return True, f"Connected successfully with model: {model}"
        elif response.status_code == 401:
            return False, "Authentication failed - Invalid API key"
        elif response.status_code == 404:
            error_data = response.json()
            return False, f"Model not found: {error_data.get('error', {}).get('message', 'Unknown error')}"
        else:
            return False, f"HTTP {response.status_code}: {response.text[:200]}"
            
    except requests.exceptions.Timeout:
        return False, "Connection timeout"
    except requests.exceptions.RequestException as e:
        return False, f"Connection error: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"

def test_anthropic() -> Tuple[bool, str]:
    """Test Anthropic/Claude API connection"""
    api_key = os.getenv('ANTHROPIC_API_KEY')
    model = os.getenv('ANTHROPIC_MODEL', 'claude-3-sonnet-20240229')
    
    if not api_key:
        return False, "No API key configured"
    
    if not api_key.startswith('sk-ant-'):
        return False, f"Invalid API key format (should start with 'sk-ant-')"
    
    try:
        headers = {
            'x-api-key': api_key,
            'anthropic-version': '2023-06-01',
            'Content-Type': 'application/json'
        }
        
        # Test with a minimal message request
        payload = {
            'model': model,
            'messages': [{'role': 'user', 'content': 'Hi'}],
            'max_tokens': 5
        }
        
        response = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers=headers,
            json=payload,
            timeout=10
        )
        
        if response.status_code == 200:
            return True, f"Connected successfully with model: {model}"
        elif response.status_code == 401:
            error_data = response.json()
            return False, f"Authentication failed: {error_data.get('error', {}).get('message', 'Invalid API key')}"
        elif response.status_code == 404:
            return False, f"Model not found: {model}"
        else:
            return False, f"HTTP {response.status_code}: {response.text[:200]}"
            
    except requests.exceptions.Timeout:
        return False, "Connection timeout"
    except requests.exceptions.RequestException as e:
        return False, f"Connection error: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"

def test_azure_foundry() -> Tuple[bool, str]:
    """Test Azure AI Foundry (Anthropic) connection"""
    endpoint = os.getenv('AZURE_AI_FOUNDRY_ENDPOINT')
    api_key = os.getenv('AZURE_AI_FOUNDRY_API_KEY')
    # Use the deployment name, not the generic model name
    model = os.getenv('AZURE_AI_FOUNDRY_DEPLOYMENT_NAME') or os.getenv('ANTHROPIC_DEFAULT_SONNET_MODEL', 'cogdep-aifoundry-dev-eus2-claude-sonnet-4-5')

    if not endpoint:
        return False, "No endpoint configured"

    if not api_key:
        return False, "No API key configured"

    if endpoint == 'https://<your-resource>.services.ai.azure.com/anthropic':
        return False, "Endpoint not configured (using placeholder)"

    try:
        # Azure AI Foundry uses different header formats - try both
        headers = {
            'api-key': api_key,
            'x-api-key': api_key,  # Also try Anthropic's standard header
            'anthropic-version': '2023-06-01',
            'Content-Type': 'application/json'
        }

        # Test with a minimal message request
        payload = {
            'model': model,
            'messages': [{'role': 'user', 'content': 'Hi'}],
            'max_tokens': 5
        }

        # Ensure endpoint includes /anthropic path
        endpoint_base = endpoint.rstrip('/')
        if not endpoint_base.endswith('/anthropic'):
            endpoint_base = f"{endpoint_base}/anthropic"
        url = f"{endpoint_base}/v1/messages"

        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=10
        )

        if response.status_code == 200:
            return True, f"Connected successfully with model: {model}"
        elif response.status_code == 401:
            error_detail = response.text[:300] if response.text else "No details"
            return False, f"Authentication failed - {error_detail}"
        elif response.status_code == 404:
            error_detail = response.text[:300] if response.text else "No details"
            return False, f"Endpoint not found or model unavailable: {model} - {error_detail}"
        else:
            return False, f"HTTP {response.status_code}: {response.text[:300]}"

    except requests.exceptions.Timeout:
        return False, "Connection timeout"
    except requests.exceptions.RequestException as e:
        return False, f"Connection error: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"

def test_ollama() -> Tuple[bool, str]:
    """Test Ollama local instance"""
    base_url = os.getenv('OLLAMA_BASE_URL', 'http://ollama:11434')
    model = os.getenv('AI_MODEL', 'llama3')
    
    # Try localhost if ollama hostname doesn't work
    test_urls = [base_url, 'http://localhost:11434']
    
    for url in test_urls:
        try:
            # Test if Ollama is running
            response = requests.get(f"{url}/api/tags", timeout=5)
            
            if response.status_code == 200:
                models_data = response.json()
                models = [m['name'] for m in models_data.get('models', [])]
                
                if models:
                    return True, f"Connected to {url}, Available models: {', '.join(models[:3])}"
                else:
                    return True, f"Connected to {url} but no models installed. Run: ollama pull {model}"
            
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.Timeout:
            continue
        except Exception as e:
            continue
    
    return False, f"Ollama not running at {base_url} or localhost:11434. Start with: ollama serve"

def test_docker_ollama() -> Tuple[bool, str]:
    """Test Docker-hosted AI (Docker Model Runner or Ollama)"""
    base_url = os.getenv('DOCKER_BASE_URL', 'http://localhost:12434')
    model = os.getenv('AI_MODEL', 'llama3')
    
    # First check if it's Docker Model Runner (uses OpenAI-compatible API)
    try:
        response = requests.get(f"{base_url}/", timeout=3)
        if response.status_code == 200 and "Docker Model Runner" in response.text:
            # It's Docker Model Runner - check for models via OpenAI API
            models_response = requests.get(f"{base_url}/engines/v1/models", timeout=3)
            if models_response.status_code == 200:
                models_data = models_response.json()
                models = [m.get('id', m.get('name', 'unknown')) for m in models_data.get('data', [])]
                
                if models:
                    return True, f"Docker Model Runner at {base_url}, models: {', '.join(models[:3])}"
                else:
                    return False, f"Docker Model Runner at {base_url} has no models. Pull one with: docker model pull ai/llama3.2"
    except Exception:
        pass
    
    # Try Ollama API endpoints
    test_urls = [
        base_url,
        'http://localhost:12434',
        'http://localhost:11434',
    ]
    
    # Remove duplicates while preserving order
    seen = set()
    unique_urls = []
    for url in test_urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    
    for url in unique_urls:
        try:
            response = requests.get(f"{url}/api/tags", timeout=3)
            
            if response.status_code == 200:
                models_data = response.json()
                models = [m['name'] for m in models_data.get('models', [])]
                
                if models:
                    return True, f"Ollama at {url}, models: {', '.join(models[:3])}"
                else:
                    return True, f"Ollama at {url} but no models. Run: docker exec ollama ollama pull {model}"
        
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.Timeout:
            continue
        except Exception:
            continue
    
    return False, f"No Docker AI at {base_url}. For Docker Model Runner: docker model pull ai/llama3.2"

def main():
    """Main test function"""
    print_header("AI Provider Connection Test")
    
    # Get active provider
    active_provider = os.getenv('AI_PROVIDER', 'openai')
    print_info(f"Active Provider: {active_provider.upper()}")
    print()
    
    results = {}
    
    # Test OpenAI
    print(f"{Colors.BOLD}Testing OpenAI...{Colors.END}")
    success, message = test_openai()
    results['openai'] = success
    
    if success:
        print_success(f"OpenAI: {message}")
        if active_provider == 'openai':
            print_info("  → Currently in use")
    else:
        print_error(f"OpenAI: {message}")
        if active_provider == 'openai':
            print_warning("  → This is your active provider but connection failed!")
    print()
    
    # Test Anthropic/Claude
    print(f"{Colors.BOLD}Testing Anthropic (Claude)...{Colors.END}")
    success, message = test_anthropic()
    results['claude'] = success
    
    if success:
        print_success(f"Anthropic: {message}")
        if active_provider == 'claude':
            print_info("  → Currently in use")
    else:
        print_error(f"Anthropic: {message}")
        if active_provider == 'claude':
            print_warning("  → This is your active provider but connection failed!")
    print()
    
    # Test Azure AI Foundry
    print(f"{Colors.BOLD}Testing Azure AI Foundry...{Colors.END}")
    success, message = test_azure_foundry()
    results['anthropic_foundry'] = success
    
    if success:
        print_success(f"Azure Foundry: {message}")
        if active_provider == 'anthropic_foundry':
            print_info("  → Currently in use")
    else:
        print_error(f"Azure Foundry: {message}")
        if active_provider == 'anthropic_foundry':
            print_warning("  → This is your active provider but connection failed!")
    print()
    
    # Test Ollama
    print(f"{Colors.BOLD}Testing Ollama (Local)...{Colors.END}")
    success, message = test_ollama()
    results['ollama'] = success
    
    if success:
        print_success(f"Ollama: {message}")
        if active_provider == 'ollama':
            print_info("  → Currently in use")
    else:
        print_error(f"Ollama: {message}")
        if active_provider == 'ollama':
            print_warning("  → This is your active provider but connection failed!")
    print()
    
    # Test Docker Ollama
    print(f"{Colors.BOLD}Testing Docker Ollama...{Colors.END}")
    success, message = test_docker_ollama()
    results['docker'] = success
    
    if success:
        print_success(f"Docker Ollama: {message}")
        if active_provider == 'docker':
            print_info("  → Currently in use")
    else:
        print_error(f"Docker Ollama: {message}")
        if active_provider == 'docker':
            print_warning("  → This is your active provider but connection failed!")
    print()
    
    # Summary
    print_header("Summary")
    
    working_providers = [name for name, status in results.items() if status]
    failed_providers = [name for name, status in results.items() if not status]
    
    print(f"✓ Working Providers ({len(working_providers)}): {', '.join(working_providers) if working_providers else 'None'}")
    print(f"✗ Failed Providers ({len(failed_providers)}): {', '.join(failed_providers) if failed_providers else 'None'}")
    print()
    
    # Check if active provider is working
    if results.get(active_provider, False):
        print_success(f"Active provider '{active_provider}' is working correctly!")
        return 0
    else:
        print_error(f"Active provider '{active_provider}' is NOT working!")
        print_warning(f"Consider switching to a working provider in .env")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(130)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)
