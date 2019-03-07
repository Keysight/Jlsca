# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

module DesTest

using Jlsca.Des
using Test

function testBitsAndBytes()
	bytes = hex2bytes("deadbeefc335")
	int = Int(0xdeadbeefc335)
	bits = BitArray([Meta.parse(string(x)) for x in "110111101010110110111110111011111100001100110101"])

	@test toBits(bytes) == toBits(int, 48)
	@test toBits(bytes) == bits
	@test toUInt64(bits) == int
end

function testSixbitsShit()
	rkbytes = ["8805bc20c812", "53e4c28209c8", "78cda2809311", "f0a10f530620", "218617580908", "6518b600701c", "b6a0f06130a0", "9e4632a0082b", "25eb43334500", "2375a3880102","f905d1c46204", "55c2997002c8", "17919690900b",  "3e08c7063620", "3b602c382960", "45bccd464025"]
	rk6bits = ["2200163c080c2012", "143e130220202708", "1e0c362220090c11", "3c0a040f14301820", "0818181716002408", "191122360007001c", "2d2a033018130220", "272418322800202b", "091e2d030c341400", "0837162322000402", "3e10171131060804", "151c0a191c000b08", "053906162409000b", "0f20230701231820", "0e36002c0e022520", "111b330d11240025"]

	for i in 1:length(rkbytes)
		bytes = hex2bytes(rkbytes[i])
		sixbits = hex2bytes(rk6bits[i])

		@test toBits(bytes) == toBits(sixbits, 6)
		@test toSixbits(toBits(bytes)) == sixbits
	end
end


function testKeyExpansion()
	key = hex2bytes("8a7400a03230da28")
	rkbytes = ["8805bc20c812", "53e4c28209c8", "78cda2809311", "f0a10f530620", "218617580908", "6518b600701c", "b6a0f06130a0", "9e4632a0082b", "25eb43334500", "2375a3880102","f905d1c46204", "55c2997002c8", "17919690900b",  "3e08c7063620", "3b602c382960", "45bccd464025"]
	rk6bits = ["2200163c080c2012", "143e130220202708", "1e0c362220090c11", "3c0a040f14301820", "0818181716002408", "191122360007001c", "2d2a033018130220", "272418322800202b", "091e2d030c341400", "0837162322000402", "3e10171131060804", "151c0a191c000b08", "053906162409000b", "0f20230701231820", "0e36002c0e022520", "111b330d11240025"]

	cd = KeyExpansion(key)

	for i in 1:16
		k = getK(cd, i)
		@test toBytes(k) == hex2bytes(rkbytes[i])
		@test toSixbits(k) == hex2bytes(rk6bits[i])
		# @printf("round %d key bytes: %s\n", i, bytes2hex(toBytes(k)))
		# @printf("round %d key 6bits: %s\n", i, bytes2hex(toSixbits(k)))
	end
end

function testKeyExpansionBackwards()
	key = [(UInt8(rand(0:255)) & 0xfe) for x in 1:8] #hex2bytes("8a7400a03230da28")

	cd = KeyExpansion(key)

	rk1num = 1
	rk1 = getK(cd, rk1num)
	rk2num = 2
	rk2 = getK(cd, rk2num)

	# try some bit errors and see what KeyExpansionBackwards does! It helps the user, yeah for real!
	# rk1[1] ⊻= 1
	# rk2[6*6+2] ⊻= 1
	# rk2[6*6+1] ⊻= 1
	recoveredkey = KeyExpansionBackwards(rk1, rk1num, rk2, rk2num)

	@test key == recoveredkey

	rk1num = 16
	rk1 = getK(cd, rk1num)
	rk2num = 15
	rk2 = getK(cd, rk2num)

	recoveredkey = KeyExpansionBackwards(rk1, rk1num, rk2, rk2num)

	@test key == recoveredkey
end

function testKeyExpansionBackwardsIncomplete()
	someinput = [rand(UInt8) for x in 1:8]
	key = [rand(UInt8) & 0xfe for x in 1:8] 
	# key = [0xfe for x in 1:8] 
	expkey = KeyExpansion(key)
	someoutput = Cipher(someinput,expkey)

	rk1num = 1
	rk1 = getK(expkey, rk1num)
	mask = falses(56)

	recoveredkey = KeyExpansionBackwards([(rk1num,rk1)],mask)
	# print(mapreduce(x -> x ? "1" : "0", *, Des.PC1(toBits(key))),"\n")
	# print(mapreduce(x -> x ? "1" : "0", *, Des.PC1(toBits(recoveredkey))),"\n")

	nrmissing = 56 - count(mask)
	idxes = Des.PC1bits[findall(x -> !x, mask)]
	# @show idxes
	recoveredkeybits = toBits(recoveredkey)
	found = false

	# @show 0:2^nrmissing-1
	for k in 0:2^nrmissing-1
		for b in 0:nrmissing-1
			if (k >> b) & 1 == 1
				recoveredkeybits[idxes[b+1]] = true
			else
				recoveredkeybits[idxes[b+1]] = false
			end
		end

		expkey2 = KeyExpansion(toBytes(recoveredkeybits))
		if Cipher(someinput, expkey2) == someoutput
			found = true
			break
		end
	end

	@test found

end

function testIP()
	input = hex2bytes("a76db873c63fe078")
	expectedIP = hex2bytes("daac332b55efa639")

	@test toBytes(IP(toBits(input))) == expectedIP
end


function testCipher()
	key = hex2bytes("CAFECEE5DEADBEEF")
	input = hex2bytes("1122334455667788")
	expectedoutput = hex2bytes("cd17b90c86f090f4")

	cd = KeyExpansion(key)
	output = Cipher(input, cd)

	@test output == expectedoutput

	plain = InvCipher(output, cd)

	@test plain == input

end

function testTdes2()
	input = hex2bytes("f1033ed6bdfea107")
	key = hex2bytes("761ec2fe00f6caa8d658b4ba70ce0c2c")
	expectedoutput = hex2bytes("5792944d5395a420")
	key1 = KeyExpansion(key[1:8])
	key2 = KeyExpansion(key[9:16])

	@test expectedoutput == TDESencrypt(input, key1, key2, key1)

	computedinput = TDESdecrypt(expectedoutput, key1, key2, key1)

	@test computedinput == input
end

function testTdes3()
	input = hex2bytes("ab81f898e3ddfe81")
	key = hex2bytes("0432028cdea6ea3060d0484086def47cc0e89c467caad6b0")
	expectedoutput = hex2bytes("8890f771124d9b01")
	key1 = KeyExpansion(key[1:8])
	key2 = KeyExpansion(key[9:16])
	key3 = KeyExpansion(key[17:24])

	@test expectedoutput == TDESencrypt(input, key1, key2, key3)

	computedinput = TDESdecrypt(expectedoutput, key1, key2, key3)

	@test computedinput == input
end

testBitsAndBytes()
testSixbitsShit()
testKeyExpansion()
testKeyExpansionBackwards()
testKeyExpansionBackwardsIncomplete()
testIP()
testCipher()
testTdes2()
testTdes3()

end
