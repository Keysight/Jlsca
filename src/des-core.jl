# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

export Cipher,InvCipher,KeyExpansion,KeyExpansionBackwards,Sbox,E,IP,getK,invP,f,invIP
export toBytes,toSixbits,toBits,toNibbles,toUInt64
export TDESencrypt,TDESdecrypt

# 64 to 64 bits
const IPbits = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]

function myinv(s, size=length(s))
  invs = fill(-1, size)
  for i in 1:length(s)
    invs[s[i]] = i
  end
  return invs
end

# 64 to 64 bits
const invIPbits = myinv(IPbits)

# 32 to 48 bits
const Ebits = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]

# 48 to 32 bits
const invEbits = myinv(Ebits)

# 32 to 32 bits
const Pbits = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]

# 32 to 32 bits
const invPbits = myinv(Pbits)

# sboxes 1 - 8: 6 to 4 bits
const S1 = collect(UInt8, [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13])

const S2 = collect(UInt8, [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9])

const S3 = collect(UInt8, [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12])

const S4 = collect(UInt8, [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14])

const S5 = collect(UInt8, [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3])

const S6 = collect(UInt8, [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13])

const S7 = collect(UInt8, [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12])

const S8 = collect(UInt8, [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11])

function Sbox(i)
	if i == 1
		return S1
	elseif i == 2
		return S2
	elseif i == 3
		return S3
	elseif i == 4
		return S4
	elseif i == 5
		return S5
	elseif i == 6
		return S6
	elseif i == 7
		return S7
	elseif i == 8
		return S8
	end
end

# 64 to 56 bits
const PC1bits = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]

# 56 to 64 bits
const invPC1bits = myinv(PC1bits, 64)

# 56 to 48 bits
const PC2bits = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]

# 48 to 56 bits
const invPC2bits = myinv(PC2bits, 56)

const shifts = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

leftrotate(bitpacked::BitVector, shifts::Int) = reverse(circshift(reverse(bitpacked), shifts))
rightrotate(bitpacked::BitVector, shifts::Int) = circshift(bitpacked, shifts)

function toUInt64(d::BitVector)
	(length(d) >= 0 && length(d) <= 64) || throw(DimensionMismatch("wrong length"))

	ret::UInt64 = 0
	for idx in 1:length(d)
		ret <<= 1
		ret |= (d[idx] ? 1 : 0)
	end

	return ret
end


function toBits(d::UInt8, bits)
	return toBits(Int64(d), bits)
end

function toBits(d::Int64, bits=64)
	(bits >= 0 && bits <= 64) || throw(DimensionMismatch("wrong length"))

	ret = BitVector(bits)
	for idx in bits:-1:1
		ret[idx] = ((d & 1) == 1 ? true : false)
		d >>= 1
	end

	return ret
end


function toBits(d::Vector{UInt8}, bitsperbyte=8, bits::Int=length(d)*bitsperbyte)
	(bits >= 0 && bits <= length(d)*bitsperbyte) || throw(DimensionMismatch("wrong length"))

	bitstring = join(map(x -> bin(x,bitsperbyte,false), d))[1:bits]
	bitpacked = BitArray([x == '1' ? 1 : 0 for x in bitstring])

	return bitpacked
end

function toBytes(d::BitVector)
	ret = zeros(UInt8, div(length(d),8) + (length(d) & 0x7 > 0 ? 1 : 0))
	for idx in 0:(length(d)-1)
		bit = (d[idx+1] ? 1 : 0)
		ret[div(idx,8)+1] &= ~(1<<(7-idx&7))
		ret[div(idx,8)+1] |= (bit<<(7-idx&7))
	end

	return ret
end

function toSixbits(d::BitVector)
	ret = zeros(UInt8, div(length(d),6) + (length(d) % 0x6 > 0 ? 1 : 0))
	for idx in 0:(length(d)-1)
		bit = (d[idx+1] ? 1 : 0)
		ret[div(idx,6)+1] &= ~(1<<(5-idx%6))
		ret[div(idx,6)+1] |= (bit<<(5-idx%6))
	end

	return ret
end


function toNibbles(d::BitVector)
	ret = zeros(UInt8, div(length(d),4) + (length(d) % 4 > 0 ? 1 : 0))
	for idx in 0:(length(d)-1)
		bit = (d[idx+1] ? 1 : 0)
		ret[div(idx,4)+1] &= ~(1<<(3-idx%4))
		ret[div(idx,4)+1] |= (bit<<(3-idx%4))
	end

	return ret
end

function KeyExpansion(k::Vector{UInt8})
	(length(k) == 8) || throw(DimensionMismatch(@sprintf("wrong key size %d", length(k))))

	cd = BitVector(56*17)
	cd[1:56] = PC1(toBits(k))

	for k in 1:16
		i = (k-1)*56
		o = k*56
		cd[o+1:o+28] = leftrotate(cd[i+1:i+28], shifts[k])
		cd[o+29:o+56] = leftrotate(cd[i+29:i+56], shifts[k])
	end

	return cd
end

function KeyExpansionBackwards(rk1::BitVector, rk2::BitVector)
	return KeyExpansionBackwards(rk1, 1, rk2, 2)
end

function KeyExpansionBackwards(rk1::BitVector, rk1Round::Int, rk2::BitVector, rk2Round::Int)
	(length(rk1) == 48 && length(rk2) == 48) || throw(DimensionMismatch("wrong key size"))

	startround = max(rk1Round, rk2Round)
	nextround = min(rk1Round, rk2Round)

	(startround != nextround) || throw(DimensionMismatch("wrong exception type but i don't know any other"))

	cd = BitVector(56*(startround+1))
	mask = bits2mask(invPC2bits)

	if rk1Round == startround
		cd[startround*56+1:startround*56+56] = invPC2(rk1)
		nextroundbits = invPC2(rk2)
	else
		cd[startround*56+1:startround*56+56] = invPC2(rk2)
		nextroundbits = invPC2(rk1)
	end

	shiftcount = 0

	for k in startround:-1:1
		i = k*56
		o = (k-1)*56

		if k == nextround
			mask2 = bits2mask(invPC2bits)
			for b in 1:56
				# if bit was set before
				if mask[b] == true
					# and bit is set in the key we're adding, they'd better be the same
					if mask2[b] == true && cd[i+b] != nextroundbits[b]
						# if not, find from which key byte we got the bit set before and print.
						bb = (b - shiftcount) % 57
						if bb <= 0
							bb += 56
						end

						@printf("mismatch in bit %d of Sbox %d key chunk of round %d versus bit %d of Sbox %d key chunk of round %d! (taking round %d value)\n", invPC2bits[b] % 6, div(invPC2bits[b],6)+1, nextround, invPC2bits[bb] %6, div(invPC2bits[bb],6)+1, startround, startround)
					end
				else
					# if we didn't have this bit before and it's valid in the key we're adding, add it
					if mask2[b] == true
						cd[i+b] = nextroundbits[b]
						mask[b] = true
					end
				end
			end
		end

		shiftcount += shifts[k]
		mask[1:28] = rightrotate(mask[1:28], shifts[k])
		mask[29:56] = rightrotate(mask[29:56], shifts[k])
		cd[o+1:o+28] = rightrotate(cd[i+1:i+28], shifts[k])
		cd[o+29:o+56] = rightrotate(cd[i+29:i+56], shifts[k])
	end

	# this won't happen if you recover with the first two DES round keys, but does happen for example when you try to recover with rounds 3 and 5
	if false in mask
		@printf("missing some bits: %s\n", string(mask))
	end

	return toBytes(invPC1(cd[1:56]))
end


function getK(cd::BitVector, i)
	o = 56*i
	return PC2(cd[o+1:o+56])
end

bits2mask(bits) =  BitArray([x != -1 for x in bits])
selectBits(data::BitVector, bits) = BitArray([(x != -1 ? data[x] : 0) for x in bits])
IP(data::BitVector) = selectBits(data, IPbits)
invIP(data::BitVector) = selectBits(data, invIPbits)
E(data::BitVector) = selectBits(data, Ebits)
P(data::BitVector) = selectBits(data, Pbits)
invP(data::BitVector) = selectBits(data, invPbits)
PC1(data::BitVector) = selectBits(data, PC1bits)
invPC1(data::BitVector) = selectBits(data, invPC1bits)
PC2(data::BitVector) = selectBits(data, PC2bits)
invPC2(data::BitVector) = selectBits(data, invPC2bits)

function Sbox(data::BitVector, sbox::Vector{UInt8})
	(length(data) == 6) || throw(DimensionMismatch("wrong length"))

	i = toUInt64(BitArray([data[x] for x in [1,6,2,3,4,5]]))

	return toBits(sbox[i+1], 4)
end

function f(R::BitVector, K::BitVector, round=0, leak::Function=(x,y)->y)
	
	(length(R) == 32 && length(K) == 48) || throw(DimensionMismatch("Wrong length"))

	ret = BitVector(32)

	tmp = E(R) .⊻ K
	tmp = leak(@sprintf("r%d.keyadd", round), tmp)
	for i in 1:8
		output = (i-1)*4
		input =  (i-1)*6
		ret[output+1:output+4] = Sbox(tmp[input+1:input+6], Sbox(i))
		leak(@sprintf("r%d.sbox%d", round, i), ret[output+1:output+4])
		leak(@sprintf("r%d.sboxXORout%d", round, i), ret[output+1:output+4] .⊻ tmp[input+3:input+6])
	end
	ret = leak(@sprintf("r%d.sbox", round), ret)

	return P(ret)
end

function Cipher(input::Vector{UInt8}, cb::BitVector, leak::Function=(x,y)->y, encrypt=true)
	(length(input) == 8 && length(cb) == 17*56) || throw(DimensionMismatch("wrong length"))

	left = 1:32
	right = 33:64

	leak(@sprintf("input"), input)

	state = IP(toBits(input))

	if encrypt
		rounds = 1:16
	else
		rounds = 16:-1:1
	end

	for round in rounds
		state = leak(@sprintf("r%d.start", round), state)
		prevstate = state[1:64]
		fout = f(state[right],getK(cb,round), round, leak)
		state[1:64] = [state[right]; fout .⊻ state[left]]
		leak(@sprintf("r%d.roundF", round), invP(state[right]))
		leak(@sprintf("r%d.roundinXORout", round), invP(state .⊻ prevstate))
	end

	state[1:64] = [state[right]; state[left]]

	ret = toBytes(invIP(state))
	leak(@sprintf("output"), ret)

end


function InvCipher(input::Vector{UInt8}, cb::BitVector, leak::Function=(x,y)->y)
	return Cipher(input, cb, leak, false)
end


function TDESencrypt(input::Vector{UInt8}, key1::BitVector, key2::BitVector=key1, key3::BitVector=key2, leak::Function=(x,y)->y)
	output1 = Cipher(input, key1, leak, true)
	output2 = Cipher(output1, key2, leak, false)
	output3 = Cipher(output2, key3, leak, true)
	return output3
end

function TDESdecrypt(input::Vector{UInt8}, key1::BitVector, key2::BitVector=key1, key3::BitVector=key2, leak::Function=(x,y)->y)
	output1 = Cipher(input, key3, leak, false)
	output2 = Cipher(output1, key2, leak, true)
	output3 = Cipher(output2, key1, leak, false)
	return output3
end
