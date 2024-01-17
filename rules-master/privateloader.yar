rule privateloader
{
  meta:
    author                    = "andretavare5"
    description               = "Detects PrivateLoader malware."
    org                       = "Bitsight"
    date                      = "2024-01-11"
    yarahub_author_twitter    = "@andretavare5"
    yarahub_reference_link    = "https://www.bitsight.com/blog/tracking-privateloader-malware-distribution-service"
    yarahub_malpedia_family   = "win.privateloader"
    yarahub_uuid              = "5916c441-16b1-42b7-acaa-114c06296f38"
    yarahub_license           = "CC BY-NC-SA 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp  = "TLP:WHITE"
    yarahub_reference_md5     = "dbf48bf522a272297266c35b965c6054"
    
  strings:
    $hdr   = "Content-Type: application/x-www-form-urlencoded" wide ascii
    $dom1  = "ipinfo.io" wide ascii
    $dom2  = "db-ip.com" wide ascii
    $dom3  = "maxmind.com" wide ascii
    $dom4  = "ipgeolocation.io" wide ascii
    $ua1   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36" wide ascii
    $ua2   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36" wide ascii
    $instr = {66 0F EF (4?|8?)} // pxor xmm(1/0) - str chunk decryption
                              
  condition:
    uint16(0) == 0x5A4D and // MZ header
    filesize > 100KB and filesize < 10MB and
    $hdr and
    any of ($dom*) and
    any of ($ua*) and
    #instr > 100
}