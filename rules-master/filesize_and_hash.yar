import "hash"
rule filesize_and_hash {
    
condition:
filesize == 901124 and hash.sha256(0, filesize) == "1a1c5cfc2a24ba5eaa67035d1ca2b5d954597de7dda0154eaef8f66d537672b0"
}