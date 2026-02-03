rule APT_LotusBlossom_Chrysalis_Loader_Warbird {
    meta:
      author = "Matt Green - @mgreen27"
      description = "Detects payload bytes in first 0x490 bytes in clipc.dll Warbird technique as described by Rapid7"
      malware_family = "Chrysalis"
      threat_actor = "APT Lotus Blossom"
      reference = "https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/"
      scope = "Microsoft signed DLLs - clipc.dll VAD section"
      date = "2026-02-03"
    strings:
        $hex1 = { EF BE AD DE }
        $hex2 = { FE AF FE CA }

    condition:
        $hex1 in (0..1167) or
        $hex2 in (0..1167)
}
