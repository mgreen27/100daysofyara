rule SUS_Zip_with_QEMU_LNK_Jan25
{
    meta:
        description = "Detects ZIP files with strings for a LNK and QEMU local dll files per CRON#TRAP campaign"
        author = "Matt Green - @mgreen27"
        reference = "https://www.securonix.com/blog/crontrap-emulated-linux-environments-as-the-latest-tactic-in-malware-staging/"
        date = "2025-01-06"

    strings:
        $payload = ".lnk"

        $import01 = "brlapi-0.8.dll"
	$import02 = "libbz2-1.dll"
	$import03 = "libcairo-2.dll"
	$import04 = "libcapstone.dll"
	$import05 = "libcurl-4.dll"
	$import06 = "libepoxy-0.dll"
	$import07 = "libfdt-1.dll"
	$import08 = "libgdk_pixbuf-2.0-0.dll"
	$import09 = "libgdk-3-0.dll"
	$import10 = "libgio-2.0-0.dll"
	$import11 = "libglib-2.0-0.dll"
	$import12 = "libgnutls-30.dll"
	$import13 = "libgobject-2.0-0.dll"
	$import14 = "libgtk-3-0.dll"
	$import15 = "libiconv-2.dll"
	$import16 = "libintl-8.dll"
	$import17 = "libjack64.dll"
	$import18 = "libjpeg-8.dll"
	$import19 = "liblzo2-2.dll"
	$import20 = "libncursesw6.dll"
	$import21 = "libnfs-14.dll"
	$import22 = "libpixman-1-0.dll"
	$import23 = "libpng16-16.dll"
	$import24 = "libsasl2-3.dll"
	$import25 = "libslirp-0.dll"
	$import26 = "libsnappy.dll"
	$import27 = "libspice-server-1.dll"
	$import28 = "libssh.dll"
	$import29 = "libssp-0.dll"
	$import30 = "libusb-1.0.dll"
	$import31 = "libusbredirparser-1.dll"
	$import32 = "libvirglrenderer-1.dll"
	$import33 = "libwinpthread-1.dll"
	$import34 = "libzstd.dll"
	$import35 = "SDL2_image.dll"
	$import36 = "SDL2.dll"
	$import37 = "zlib1.dll"

    condition:
        uint16(0) == 0x4B50 and $payload
        and 25 of ($import*)
}
