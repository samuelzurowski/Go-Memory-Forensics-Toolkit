rule Go_MagicBytes
{
	meta:  
		desc = ""
		author = ""
		version = ""
		last_modified = ""
    strings:
        // $magic_bytes_lookup = {(FF FF FF FB | FB FF FF FF) 00 00} 
        $magic_bytes_lookup16 = {(FF FF FF FA | FA FF FF FF) 00 00 01 08} 
		// $test = {FA FF FF FF 00 00 08}
	condition:
		$magic_bytes_lookup16
}