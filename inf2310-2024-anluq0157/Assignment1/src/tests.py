import hashlib

def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def integrity_check(original_files, received_files):
    """Check the integrity of pairs of original and received files."""
    assert len(original_files) == len(received_files), "Lists must have the same length."
    
    for original, received in zip(original_files, received_files):
        original_hash = calculate_file_hash(original)
        received_hash = calculate_file_hash(received)
        
        if original_hash == received_hash:
            print(f"PASS: Integrity check for {original} and {received}")
        else:
            print(f"FAIL: Integrity check for {original} and {received}")

# Example usage
original_files = ['./plaintext.txt', './plaintext2.txt', './plaintext3.txt', './plaintext4.txt', './plaintext5.txt']
received_files = ['./received_file.txt', './received_file2.txt', './received_file3.txt', './received_file4.txt', './received_file5.txt']

integrity_check(original_files, received_files)
