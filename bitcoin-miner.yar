/*
Bitcoin Miner
*/

rule universal_bitcoin_miner : Miner
{
	meta:
		author="Kevin Falcoz"
		date="24/12/2019"
		description="Bitcoin Miner"
		
	strings:
		$signature1="E:\CryptoNight\bitmonero-master\src\miner\Release\Crypto.pdb"
		$signature2="http://%s/test.html?%d"
		
	condition:
		$signature1 and $signature2
}
