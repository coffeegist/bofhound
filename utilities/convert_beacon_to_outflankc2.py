#!/usr/bin/env python3
"""
Convert beacon_202.log to OutflankC2 JSON format.

This script parses Cobalt Strike beacon logs containing ldapsearch operations
and converts them to the OutflankC2 JSON format for testing purposes.
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Optional


def parse_beacon_log(log_file_path: str) -> List[Dict[str, str]]:
    """
    Parse beacon log file and extract ldapsearch operations.
    
    Args:
        log_file_path: Path to the beacon log file
        
    Returns:
        List of dictionaries containing ldapsearch data
    """
    ldapsearch_operations = []
    
    with open(log_file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Look for ldapsearch input command
        if '[input] <neo> ldapsearch' in line:
            print(f"Found ldapsearch command at line {i + 1}: {line}")
            
            # Extract the command for reference
            command = line.split('[input] <neo> ')[1]
            
            # Skip to the output sections
            i += 1
            output_lines = []
            collecting_output = False
            
            while i < len(lines):
                current_line = lines[i]
                
                # Start collecting when we see [output]
                if '[output]' in current_line:
                    collecting_output = True
                    i += 1
                    continue
                
                # Stop collecting when we hit retreived results or next command
                if collecting_output:
                    if 'retreived' in current_line and 'results total' in current_line:
                        # Include the results line and break
                        output_lines.append(current_line.strip())
                        print(f"Found end of ldapsearch at line {i + 1}: {current_line.strip()}")
                        break
                    elif '[input]' in current_line:
                        # Hit next command, don't include this line
                        i -= 1  # Back up one line
                        break
                    else:
                        # Collect output content, skipping 'received output:' prefix
                        content = current_line
                        if content.startswith('received output:'):
                            content = content[len('received output:'):].lstrip()
                        if content.strip():  # Only add non-empty lines
                            output_lines.append(content.rstrip())
                
                i += 1
            
            # Join all output lines to create the response
            if output_lines:
                response = '\n'.join(output_lines)
                ldapsearch_operations.append({
                    'command': command,
                    'response': response
                })
                print(f"Extracted ldapsearch operation with {len(output_lines)} lines of output")
        
        i += 1
    
    return ldapsearch_operations


def convert_to_outflankc2_json(ldapsearch_operations: List[Dict[str, str]], output_file: str):
    """
    Convert extracted ldapsearch operations to OutflankC2 JSON format.
    
    Args:
        ldapsearch_operations: List of ldapsearch operations
        output_file: Path to output JSON file
    """
    timestamp = "2025-01-01 12:30:32 UTC"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for i, operation in enumerate(ldapsearch_operations):
            # Create the OutflankC2 JSON structure
            json_obj = {
                "event_type": "task_response",
                "task": {
                    "name": "ldapsearch",
                    "response": operation['response']
                }
            }
            
            # Write as single line JSON with timestamp prefix
            json_line = f'{timestamp} {json.dumps(json_obj, separators=(",", ":"))}'
            f.write(json_line + '\n')
            
            print(f"Wrote ldapsearch operation {i + 1} to JSON file")


def main():
    """Main conversion function."""
    input_file = "tests/test_data/ldapsearchbof_logs/beacon_202.log"
    output_file = "tests/test_data/beacon_202.json"
    
    print(f"Converting {input_file} to {output_file}")
    
    # Check if input file exists
    if not Path(input_file).exists():
        print(f"Error: Input file {input_file} does not exist")
        return
    
    # Parse the beacon log
    ldapsearch_operations = parse_beacon_log(input_file)
    
    if not ldapsearch_operations:
        print("No ldapsearch operations found in the beacon log")
        return
    
    print(f"Found {len(ldapsearch_operations)} ldapsearch operations")
    
    # Convert to OutflankC2 JSON format
    convert_to_outflankc2_json(ldapsearch_operations, output_file)
    
    print(f"Conversion complete! Output written to {output_file}")
    print(f"Generated {len(ldapsearch_operations)} JSON entries")


if __name__ == "__main__":
    main()