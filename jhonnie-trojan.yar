/*
Jhonnie Trojan
*/

rule jhonnie : Trojan
{
	meta:
		author="Kevin Falcoz"
		date="24/12/2019"
		description="Jhonnie Trojan"
		
	strings:
		$signature1="\Desktop\Home\Code\Mfix\Release\Mfix.pdb"
		
	condition:
		$signature1
}
