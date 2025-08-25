#!/usr/bin/env python3
"""
AutoPwn - Ultimate Autonomous Python Deobfuscation Library
==========================================================

The most advanced, fully autonomous deobfuscation tool.

Usage:
    import autopwn
    code = autopwn.decode(encrypted_data)
    with open('code.txt', 'w') as f:
        f.write(code)

Features:
- Unlimited layer extraction
- Automatic pattern detection
- Self-healing error recovery
- Advanced heuristics
- Zero configuration needed
"""

import base64
import binascii
import bz2
import gzip
import hashlib
import io
import json
import lzma
import math
import os
import re
import sys
import time
import urllib.parse
import zlib
from typing import Union, Optional, List, Dict, Any, Tuple

class AutoPwn:
    """The ultimate autonomous deobfuscation engine."""
    
    def __init__(self):
        self.version = "2.0.0"
        self.max_layers = 1000  # Virtually unlimited
        self.seen_hashes = set()
        self.extraction_log = []
        self.debug = False
        
    def _log(self, message: str, level: str = "INFO"):
        """Internal logging system."""
        if self.debug:
            print(f"[{level}] {message}")
        self.extraction_log.append(f"[{level}] {message}")
    
    def _to_bytes(self, data: Union[bytes, str]) -> bytes:
        """Convert input to bytes intelligently."""
        if isinstance(data, bytes):
            return data
        elif isinstance(data, str):
            return data.encode('utf-8', errors='replace')
        else:
            return str(data).encode('utf-8', errors='replace')
    
    def _to_string(self, data: Union[bytes, str]) -> str:
        """Convert input to string intelligently."""
        if isinstance(data, str):
            return data
        elif isinstance(data, bytes):
            # Try multiple encodings
            for encoding in ['utf-8', 'latin-1', 'cp1252', 'ascii']:
                try:
                    return data.decode(encoding)
                except UnicodeDecodeError:
                    continue
            # Fallback with error handling
            return data.decode('utf-8', errors='replace')
        else:
            return str(data)
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0
        
        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1
        
        entropy = 0.0
        length = len(data)
        for count in frequency:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _ascii_ratio(self, data: bytes) -> float:
        """Calculate ratio of printable ASCII characters."""
        if not data:
            return 0.0
        printable = sum(1 for x in data if 32 <= x <= 126 or x in (9, 10, 13))
        return printable / len(data)
    
    def _python_score(self, text: str) -> float:
        """Advanced Python code detection."""
        if not text:
            return 0.0
        
        # Python keywords and patterns
        keywords = [
            'def ', 'class ', 'import ', 'from ', 'lambda', 'return',
            'try:', 'except', 'exec', 'eval', 'with ', 'for ', 'while ',
            'if ', 'elif ', 'else:', 'print(', '__name__', '__import__',
            'True', 'False', 'None', 'and ', 'or ', 'not ', 'in ', 'is ',
            'yield', 'async ', 'await ', 'global ', 'nonlocal ', 'pass',
            'break', 'continue', 'del ', 'assert ', 'raise ', 'finally:'
        ]
        
        patterns = [
            r'def\s+\w+\s*\(',  # Function definitions
            r'class\s+\w+\s*[:\(]',  # Class definitions
            r'import\s+\w+',  # Import statements
            r'from\s+\w+\s+import',  # From imports
            r'if\s+__name__\s*==\s*["\']__main__["\']',  # Main check
            r'\.decode\(',  # Decode calls
            r'\.encode\(',  # Encode calls
            r'\.join\(',  # Join calls
            r'\.split\(',  # Split calls
            r'\.format\(',  # Format calls
            r'f["\'][^"\']*{[^}]+}',  # F-strings
        ]
        
        score = 0
        text_lower = text.lower()
        
        # Keyword scoring
        for keyword in keywords:
            if keyword.lower() in text_lower:
                score += 1
        
        # Pattern scoring
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                score += 2
        
        # Syntax patterns
        if '(' in text and ')' in text:
            score += 0.5
        if '{' in text and '}' in text:
            score += 0.5
        if '[' in text and ']' in text:
            score += 0.5
        if ':' in text and ('\n' in text or '\r' in text):
            score += 1
        if '=' in text and not text.count('=') > len(text) / 5:
            score += 0.5
        
        # Indentation patterns (Python-specific)
        lines = text.split('\n')
        indented_lines = sum(1 for line in lines if line.startswith(('    ', '\t')))
        if len(lines) > 5 and indented_lines / len(lines) > 0.1:
            score += 2
        
        return min(1.0, score / 15.0)
    
    def _is_final_code(self, content: str) -> Tuple[bool, float]:
        """Advanced detection of final deobfuscated code."""
        content_bytes = self._to_bytes(content)
        
        # Check if it contains more obfuscation patterns
        obfuscation_patterns = [
            b"exec((_)(b'",
            b"__import__('zlib').decompress(",
            b"__import__('base64').b64decode(",
            b"[::-1])",
            b"exec(compile(",
            b"eval(compile(",
        ]
        
        has_obfuscation = any(pattern in content_bytes for pattern in obfuscation_patterns)
        
        # Calculate quality metrics
        ascii_ratio = self._ascii_ratio(content_bytes)
        python_score = self._python_score(content)
        entropy = self._calculate_entropy(content_bytes[:1000])  # Check first 1KB
        
        # Quality score calculation
        quality_score = (
            ascii_ratio * 0.3 +
            python_score * 0.5 +
            (1.0 if not has_obfuscation else 0.0) * 0.2
        )
        
        # Additional checks for final code
        has_meaningful_content = len(content.strip()) > 50
        has_python_syntax = any(keyword in content.lower() for keyword in ['def ', 'import ', 'class ', 'print('])
        
        is_final = (
            not has_obfuscation and
            has_meaningful_content and
            ascii_ratio > 0.7 and
            python_score > 0.1 and
            entropy < 7.5
        )
        
        return is_final, quality_score
    
    def _extract_payload_boundaries(self, content: str) -> Optional[str]:
        """Extract payload from various obfuscation patterns."""
        patterns = [
            # Standard exec pattern
            (r"exec\(.*?\(b'([^']+)'\)\)", 1),
            # Lambda exec pattern
            (r"exec\(\(_\)\(b'([^']+)'\)\)", 1),
            # Direct base64 pattern
            (r"b'([A-Za-z0-9+/=]{50,})'", 1),
            # Compressed data pattern
            (r"decompress\(.*?b64decode\(.*?b'([^']+)'", 1),
            # Reversed base64 pattern
            (r"b64decode\(([^)]+)\[::-1\]\)", 1),
        ]
        
        for pattern, group in patterns:
            match = re.search(pattern, content, re.DOTALL)
            if match:
                payload = match.group(group)
                # Clean up the payload
                payload = payload.replace('"', '').replace("'", "")
                if len(payload) > 20:  # Minimum payload size
                    return payload
        
        return None
    
    def _try_base64_decode(self, data: str) -> Optional[bytes]:
        """Advanced base64 decoding with multiple attempts."""
        # Clean the data
        data = data.strip().replace(' ', '').replace('\n', '').replace('\r', '')
        data = data.replace('-', '+').replace('_', '/')  # URL-safe to standard
        
        # Try different padding scenarios
        for padding in range(4):
            try:
                padded_data = data + '=' * padding
                return base64.b64decode(padded_data)
            except Exception:
                continue
        
        # Try without validation
        try:
            return base64.b64decode(data, validate=False)
        except Exception:
            pass
        
        return None
    
    def _try_decompress(self, data: bytes) -> Optional[bytes]:
        """Try multiple decompression methods."""
        methods = [
            ('zlib', lambda x: zlib.decompress(x)),
            ('gzip', lambda x: gzip.decompress(x)),
            ('bz2', lambda x: bz2.decompress(x)),
            ('lzma', lambda x: lzma.decompress(x)),
            ('zlib_raw', lambda x: zlib.decompress(x, -15)),  # Raw deflate
        ]
        
        for method_name, method in methods:
            try:
                result = method(data)
                self._log(f"Successfully decompressed with {method_name}")
                return result
            except Exception:
                continue
        
        return None
    
    def _single_layer_decode(self, content: str) -> Optional[bytes]:
        """Decode a single layer of obfuscation."""
        # Extract payload
        payload = self._extract_payload_boundaries(content)
        if not payload:
            return None
        
        self._log(f"Extracted payload: {len(payload)} characters")
        
        # Try reversing first (common pattern)
        reversed_payload = payload[::-1]
        
        # Try base64 decode
        decoded = self._try_base64_decode(reversed_payload)
        if not decoded:
            # Try without reversing
            decoded = self._try_base64_decode(payload)
        
        if not decoded:
            self._log("Failed to base64 decode payload", "ERROR")
            return None
        
        self._log(f"Base64 decoded: {len(decoded)} bytes")
        
        # Try decompression
        decompressed = self._try_decompress(decoded)
        if decompressed:
            self._log(f"Decompressed: {len(decompressed)} bytes")
            return decompressed
        
        # Return decoded even if decompression failed
        return decoded
    
    def _detect_cycle(self, content_hash: str) -> bool:
        """Detect infinite loops in deobfuscation."""
        if content_hash in self.seen_hashes:
            self._log("Cycle detected - stopping extraction", "WARNING")
            return True
        self.seen_hashes.add(content_hash)
        return False
    
    def _autonomous_extract(self, data: Union[bytes, str]) -> str:
        """The main autonomous extraction engine."""
        current_content = self._to_string(data)
        layer_count = 0
        
        self._log(f"Starting autonomous extraction")
        self._log(f"Initial content size: {len(current_content)} characters")
        
        while layer_count < self.max_layers:
            layer_count += 1
            self._log(f"Processing layer {layer_count}")
            
            # Check for cycles
            content_hash = hashlib.sha256(current_content.encode()).hexdigest()
            if self._detect_cycle(content_hash):
                break
            
            # Check if this is final code
            is_final, quality_score = self._is_final_code(current_content)
            self._log(f"Layer {layer_count} quality score: {quality_score:.3f}")
            
            if is_final:
                self._log(f"Final code detected at layer {layer_count}!")
                break
            
            # Try to extract next layer
            next_layer = self._single_layer_decode(current_content)
            if next_layer is None:
                self._log(f"No more layers found at layer {layer_count}")
                break
            
            # Convert to string and continue
            current_content = self._to_string(next_layer)
            self._log(f"Layer {layer_count} extracted: {len(current_content)} characters")
            
            # Emergency brake for infinite loops
            if layer_count > 100 and layer_count % 50 == 0:
                self._log(f"Deep extraction at layer {layer_count} - checking quality")
                is_final, quality_score = self._is_final_code(current_content)
                if quality_score > 0.7:
                    self._log(f"High quality code found at layer {layer_count} - stopping")
                    break
        
        self._log(f"Extraction completed after {layer_count} layers")
        return current_content
    
    def decode(self, data: Union[bytes, str], debug: bool = False) -> str:
        """
        Main decode function - the only method you need to call.
        
        Args:
            data: Encrypted/obfuscated data (bytes or string)
            debug: Enable debug output
            
        Returns:
            Deobfuscated Python code as string
        """
        self.debug = debug
        self.seen_hashes.clear()
        self.extraction_log.clear()
        
        start_time = time.time()
        self._log("AutoPwn v2.0.0 - Ultimate Autonomous Deobfuscation")
        
        try:
            # Handle file input
            if isinstance(data, str) and os.path.isfile(data):
                self._log(f"Reading from file: {data}")
                with open(data, 'rb') as f:
                    file_data = f.read()
                # Try to decode as text first
                try:
                    data = file_data.decode('utf-8')
                except UnicodeDecodeError:
                    data = file_data
            
            # Perform autonomous extraction
            result = self._autonomous_extract(data)
            
            end_time = time.time()
            self._log(f"Extraction completed in {end_time - start_time:.2f} seconds")
            
            # Final quality check
            is_final, quality_score = self._is_final_code(result)
            self._log(f"Final quality score: {quality_score:.3f}")
            
            if debug:
                print(f"\n[AUTOPWN] Extraction completed!")
                print(f"[AUTOPWN] Final code size: {len(result)} characters")
                print(f"[AUTOPWN] Quality score: {quality_score:.3f}")
                print(f"[AUTOPWN] Processing time: {end_time - start_time:.2f}s")
            
            return result
            
        except Exception as e:
            self._log(f"Fatal error during extraction: {e}", "ERROR")
            if debug:
                import traceback
                traceback.print_exc()
            return f"# AutoPwn extraction failed: {e}\n# Original data:\n{self._to_string(data)}"
    
    def get_log(self) -> List[str]:
        """Get the extraction log."""
        return self.extraction_log.copy()
    
    def save_log(self, filename: str = "autopwn.log"):
        """Save extraction log to file."""
        with open(filename, 'w') as f:
            f.write('\n'.join(self.extraction_log))

# Global instance for easy usage
_autopwn_instance = AutoPwn()

# Public API functions
def decode(data: Union[bytes, str], debug: bool = False) -> str:
    """
    Decode obfuscated Python code automatically.
    
    Usage:
        import autopwn
        code = autopwn.decode(encrypted_data)
        
    Args:
        data: Encrypted/obfuscated data (bytes, string, or file path)
        debug: Enable debug output
        
    Returns:
        Deobfuscated Python code as string
    """
    return _autopwn_instance.decode(data, debug)

def get_log() -> List[str]:
    """Get the extraction log from the last decode operation."""
    return _autopwn_instance.get_log()

def save_log(filename: str = "autopwn.log"):
    """Save extraction log to file."""
    return _autopwn_instance.save_log(filename)

# Version info
__version__ = "1.0.0"
__author__ = "AutoPwn Team"
__description__ = "Ultimate Autonomous Python Deobfuscation Library"

if __name__ == "__main__":
    # CLI interface
    import argparse
    parser = argparse.ArgumentParser(description="AutoPwn - Ultimate Autonomous Deobfuscation")
    parser.add_argument("input", help="Input file or string to deobfuscate")
    parser.add_argument("-o", "--output", default="deobfuscated_code.py", help="Output file")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    parser.add_argument("-l", "--log", help="Save log to file")
    
    args = parser.parse_args()
    
    print("🚀 AutoPwn v1.0.0 - Ultimate Autonomous Deobfuscation")
    print("=" * 60)
    
    result = decode(args.input, debug=args.debug)
    
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(result)
    
    print(f"✅ Deobfuscated code saved to: {args.output}")
    
    if args.log:
        save_log(args.log)
        print(f"📄 Log saved to: {args.log}")
