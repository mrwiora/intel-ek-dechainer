#!/usr/bin/env python3
import os
import sys
import argparse
import subprocess

def extract_certificates(input_file, output_dir=None, base_name_prefix="intel-int", start_index=3):
    """
    Extract individual certificates from a DER chain file, save them with sequentially numbered names,
    and convert them to PEM format using OpenSSL
    
    Args:
        input_file: Path to the input DER chain file
        output_dir: Directory to save extracted certificates (if None, use current directory)
        base_name_prefix: Prefix for certificate filenames
        start_index: Starting index for certificate numbering (first certificate will be {prefix}{start_index})
    """
    # Set output directory to current directory if not specified
    if output_dir is None:
        output_dir = os.getcwd()
    else:
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    # Read the input file
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # List to store positions of certificates
    cert_positions = []
    
    # Look for certificate markers in the file
    i = 0
    while i < len(data) - 4:  # Need at least 4 bytes for a minimal ASN.1 structure
        # Check for ASN.1 SEQUENCE tag (0x30)
        if data[i] == 0x30:
            length_byte = data[i + 1]
            
            # Handle different ASN.1 length encodings
            if length_byte < 128:
                # Short form: 1 byte length
                length = length_byte
                header_size = 2  # tag (1) + length (1)
            elif length_byte == 0x81:
                # Long form: length is in next 1 byte
                if i + 2 >= len(data):
                    i += 1
                    continue
                length = data[i + 2]
                header_size = 3  # tag (1) + length marker (1) + length (1)
            elif length_byte == 0x82:
                # Long form: length is in next 2 bytes
                if i + 3 >= len(data):
                    i += 1
                    continue
                length = (data[i + 2] << 8) | data[i + 3]
                header_size = 4  # tag (1) + length marker (1) + length (2)
            elif length_byte == 0x83:
                # Long form: length is in next 3 bytes
                if i + 4 >= len(data):
                    i += 1
                    continue
                length = (data[i + 2] << 16) | (data[i + 3] << 8) | data[i + 4]
                header_size = 5  # tag (1) + length marker (1) + length (3)
            else:
                # Not a valid certificate start or unsupported format
                i += 1
                continue
            
            # Calculate the total certificate size
            total_size = header_size + length
            
            # Basic validation - reasonable certificate size and not exceeding file bounds
            if 128 <= length <= 10000 and i + total_size <= len(data):
                # Check for additional certificate indicators
                # X.509 cert typically has SEQUENCE followed by another SEQUENCE or INTEGER
                if header_size < len(data) and (
                    data[i + header_size] == 0x30 or  # SEQUENCE
                    data[i + header_size] == 0x02):   # INTEGER
                    cert_positions.append((i, total_size))
                    # Skip past this certificate
                    i += total_size
                    continue
        
        i += 1
    
    # Extract and save each certificate
    for idx, (start, size) in enumerate(cert_positions):
        cert_index = start_index + idx
        base_name = f"{base_name_prefix}{cert_index}"
        
        der_file = os.path.join(output_dir, f"{base_name}.der")
        pem_file = os.path.join(output_dir, f"{base_name}.pem")
        
        cert_data = data[start:start + size]
        
        # Save DER file
        with open(der_file, 'wb') as f:
            f.write(cert_data)
        
        print(f"Extracted certificate {idx + 1} ({size} bytes) to {der_file}")
        
        # Convert to PEM using OpenSSL
        try:
            # Using OpenSSL to convert DER to PEM
            cmd = ["openssl", "x509", "-inform", "DER", "-in", der_file, "-outform", "PEM", "-out", pem_file]
            
            # Run the command
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Check if the command was successful
            if result.returncode == 0:
                print(f"Converted to PEM format: {pem_file}")
            else:
                print(f"Error converting to PEM: {result.stderr}")
                
                # Try alternative command if the certificate is not recognized as X.509
                alt_cmd = ["openssl", "x509", "-in", der_file, "-out", pem_file]
                alt_result = subprocess.run(alt_cmd, capture_output=True, text=True)
                
                if alt_result.returncode == 0:
                    print(f"Converted to PEM format (using alternate command): {pem_file}")
                else:
                    print(f"Failed to convert using alternate command: {alt_result.stderr}")
                    
        except Exception as e:
            print(f"Error running OpenSSL command: {str(e)}")
    
    return len(cert_positions)

def main():
    parser = argparse.ArgumentParser(description='Extract certificates from a DER chain file')
    parser.add_argument('input_file', help='Path to the input DER chain file')
    parser.add_argument('-o', '--output-dir', default=None, 
                        help='Directory to save extracted certificates (default: current directory)')
    parser.add_argument('-p', '--prefix', default="intel-int", 
                        help='Prefix for certificate filenames (default: intel-int)')
    parser.add_argument('-s', '--start-index', type=int, default=3, 
                        help='Starting index for certificate numbering (default: 3)')
    
    args = parser.parse_args()
    
    if not os.path.isfile(args.input_file):
        print(f"Error: Input file '{args.input_file}' not found")
        return 1
    
    try:
        count = extract_certificates(args.input_file, args.output_dir, args.prefix, args.start_index)
        if count > 0:
            print(f"Successfully extracted {count} certificates")
            for i in range(count):
                print(f"  {args.prefix}{args.start_index + i}")
        else:
            print("No certificates found in the input file")
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
