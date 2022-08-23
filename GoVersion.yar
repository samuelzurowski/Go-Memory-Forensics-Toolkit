rule go_magic_test {
	strings: 
		$magic_bytes_lookup16 = { FA FF FF FF 00 00 01 08 }
		$magic_bytes_lookup16_endian =  {FF FF FF FA 00 00 01 08}
		$magic_bytes_12 = { FF FF FF FB 00 00 01 08 } 
		$magic_bytes_12_endian = { FB FF FF FF 00 00 01 08 } 
	condition:
		any of them
}