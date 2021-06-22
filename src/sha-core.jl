# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Printf

export sha1,sha256,hmacsha1,hmacsha256,update,final,Sha1state,Sha256state
export Ch,Maj

Ch(x::UInt32,y::UInt32,z::UInt32) = (x & y) ⊻ (~x & z)
Maj(x::UInt32,y::UInt32,z::UInt32) = (x & y) ⊻ (x & z) ⊻ (y & z)
rotl(value::UInt32, count::Int) = (value<<count) | (value>>( (-count) & 0b11111 ))
rotr(value::UInt32, count::Int) = (value>>count) | (value<<( (-count) & 0b11111 ))
Parity(x::UInt32,y::UInt32,z::UInt32) = x ⊻ y ⊻ z

function f(t::Int,a::UInt32,b::UInt32,c::UInt32)
	if 0 <= t <= 19
		return Ch(a,b,c)
	elseif 20 <= t <= 39 || 60 <= t <= 79
		return Parity(a,b,c)
	elseif 40 <= t <= 59
		return Maj(a,b,c)
	else 
		throw(ErrorException("AAh"))
	end
end

function K(t)
	if 0 <= t <= 19
		return UInt32(0x5a827999)
	elseif 20 <= t <= 39
		return UInt32(0x6ed9eba1)
	elseif 40 <= t <= 59
		return UInt32(0x8f1bbcdc)
	elseif 60 <= t <= 79
		return UInt32(0xca62c1d6)
	else 
		throw(Error("AAh"))
	end
end

padlen(msgLen::Int) = (Int(448) - (msgLen*8 + 1)) & ((2^9)-1)

const SHA1H00 = UInt32(0x67452301)
const SHA1H01 = UInt32(0xefcdab89)
const SHA1H02 = UInt32(0x98badcfe)
const SHA1H03 = UInt32(0x10325476)
const SHA1H04 = UInt32(0xc3d2e1f0)

const sha1blocksizebytes = 64

abstract type Shastate end

mutable struct Sha1state <: Shastate
	H::Vector{UInt32}
	block::Vector{UInt8}
	free::Int
	msgLen::Int
	rnd::Int
	W:: Vector{UInt32}
	decodefn::Function
	encodefn::Function
	Sha1state() = new([SHA1H00, SHA1H01, SHA1H02, SHA1H03, SHA1H04], zeros(UInt8, sha1blocksizebytes), sha1blocksizebytes, 0, 0, zeros(UInt32, 80),ntoh,hton)
end

function calcW(state::Sha1state, Mi::AbstractVector{UInt32})
	W = state.W

	for t in 1:16
		W[t] = Mi[t]
	end

	for t in 17:80
		W[t] = rotl(W[t-3] ⊻ W[t-8] ⊻ W[t-14] ⊻ W[t-16], 1) 
	end

	return W
end 

function iteration(W::UInt32,t::Int,a::UInt32,b::UInt32,c::UInt32,d::UInt32,e::UInt32,leak::Function=(x,y)->x)
	fout = f(t,b,c,d)
	T = rotl(a,5) + fout + e + K(t) + W
	leak(@sprintf("T%d", t), T)
	leak(@sprintf("F%d", t), fout)
	e = d
	d = c
	c = rotl(b, 30)
	b = a
	a = T

	return (a,b,c,d,e)
end

function inviteration(W,t,a1,b1,c1,d1,e1)
	a0 = b1
	b0 = rotr(c1,30)
	c0 = d1
	d0 = e1
	e0 = a1 - (rotl(a0,5) + f(t,b0,c0,d0) + K(t) + W)
	return (a0,b0,c0,d0,e0)
end

function loop(W, a, b, c, d ,e, leak::Function=(x,y)->x)
	for t in 0:79
		(a,b,c,d,e) = iteration(W[t+1],t,a,b,c,d,e,leak)
	end
	return (a,b,c,d,e)
end

function round(state::Sha1state, rnd::Int, leak::Function=(x,y)->x)
	# block is big endian
	W = calcW(state, map(state.decodefn, reinterpret(UInt32,state.block)))
	a = state.H[1+0]
	b = state.H[1+1]
	c = state.H[1+2]
	d = state.H[1+3]
	e = state.H[1+4]
	for t in 0:79
		fout = f(t,b,c,d)
		T = rotl(a,5) + fout + e + K(t) + W[t+1]
		leak("T", T)
		leak("F", fout)
		e = d
		d = c
		c = rotl(b, 30)
		b = a
		a = T
	end
	leak("a", a)
	leak("b", b)
	leak("c", c)
	leak("d", d)
	leak("e", e)
	state.H[1+0] = a + state.H[1+0]
	state.H[1+1] = b + state.H[1+1]
	state.H[1+2] = c + state.H[1+2]
	state.H[1+3] = d + state.H[1+3]
	state.H[1+4] = e + state.H[1+4]
end

function update(state::Shastate, msg::AbstractVector{UInt8}, leak::Function=(x,y)->x)

	# update the msg length
	state.msgLen += length(msg)

	msgOffset = 1

	while msgOffset <= length(msg)

		# fill up the block buffer
		bl = min(state.free, length(msg) - msgOffset + 1)
		blockOffset = length(state.block) - state.free + 1

		state.block[blockOffset:(blockOffset + bl - 1)] = msg[msgOffset:(msgOffset + bl - 1)]
		msgOffset += bl
		state.free -= bl

		# flush if it's full
		if state.free == 0
			round(state, state.rnd, leak)
			state.rnd += 1
			state.free = sha1blocksizebytes
		end
	end
end

function final(state::Shastate, leak::Function=(x,y)->x)
	padlenBits = padlen(state.msgLen)
	paddedMsgLen = (padlenBits + 1 + 64) >> 3
	paddedMsg = zeros(UInt8, paddedMsgLen)	
	paddedMsg[1] = 0x80
	len64 = UInt64(state.msgLen*8)
	paddedMsg[end-8+1:end] = reinterpret(UInt8, [state.encodefn(len64)])


	update(state, paddedMsg, leak)

	# there should be no residual data in state.block
	if state.free != sha1blocksizebytes
		throw(ErrorException("bad hat harry"))
	end

	# output is big endian
	return reinterpret(UInt8, map(state.encodefn, state.H))
end

function sha1(msg::AbstractVector{UInt8}, leak::Function=(x,y)->x)
	state = Sha1state()
	update(state, msg, leak)
	return final(state, leak)	
end

function K0(key::AbstractVector{UInt8})
	if length(key) == sha1blocksizebytes
		return key
	elseif length(key) > sha1blocksizebytes
		hashed = sha1(key)
		return [hashed; [0x00 for i in 1:(sha1blocksizebytes - length(hashed))]]
	else
		return [key; [0x00 for i in 1:(sha1blocksizebytes - length(key))]]
	end
end


function hmac(::Type{T}, key::AbstractVector{UInt8}, msg::AbstractVector{UInt8}) where {T<:Shastate}
	innerstate = T()
	innerkey = K0(key) .⊻ 0x36
	update(innerstate, innerkey)
	update(innerstate, msg)
	outerstate = T()
	outerkey = K0(key) .⊻ 0x5c
	update(outerstate, [outerkey; final(innerstate)])
	return final(outerstate)
end

function hmacsha1(key::AbstractVector{UInt8}, msg::AbstractVector{UInt8})
	return hmac(Sha1state,key,msg)
end

SHA256H00 = UInt32(0x6A09E667)
SHA256H01 = UInt32(0xBB67AE85)
SHA256H02 = UInt32(0x3C6EF372)
SHA256H03 = UInt32(0xA54FF53A)
SHA256H04 = UInt32(0x510E527F)
SHA256H05 = UInt32(0x9B05688C)
SHA256H06 = UInt32(0x1F83D9AB)
SHA256H07 = UInt32(0x5BE0CD19)

mutable struct Sha256state <: Shastate
	H::Vector{UInt32}
	block::Vector{UInt8}
	free::Int
	msgLen::Int
	rnd::Int
	decodefn::Function
	encodefn::Function
	Sha256state() = new([SHA256H00, SHA256H01, SHA256H02, SHA256H03, SHA256H04, SHA256H05, SHA256H06, SHA256H07], zeros(UInt8, sha1blocksizebytes), sha1blocksizebytes, 0, 0,ntoh,hton)
end

export ∑0, ∑1

∑0(x::UInt32) = rotr(x,2) ⊻ rotr(x,13) ⊻ rotr(x,22)
∑1(x::UInt32) = rotr(x,6) ⊻ rotr(x,11) ⊻ rotr(x,25)
σ0(x::UInt32) = rotr(x,7) ⊻ rotr(x,18) ⊻ (x >> 3)
σ1(x::UInt32) = rotr(x,17) ⊻ rotr(x,19) ⊻ (x >> 10)

export K256

const K256 = [
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

function calcW(state::Sha256state, Mi)
	W = zeros(UInt32, 64)

	for t in 1:16
		W[t] = Mi[t]
	end

	for t in 17:64
		W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16] 
	end

	return W
end 

function iteration(W,t,a,b,c,d,e,f,g,h,leak::Function=(x,y)->x)
	leak("a_$t",a)
	leak("b_$t",b)
	leak("c_$t",c)
	leak("d_$t",d)
	leak("e_$t",e)
	leak("f_$t",f)
	leak("g_$t",g)
	leak("h_$t",h)
	leak("W_$t",W)
	T1 = h + ∑1(e) + Ch(e,f,g) + K256[t+1] + W
	T2 = ∑0(a) + Maj(a,b,c)
	leak("T1_$t", T1)
	leak("T2_$t", T2)
	h = g
	g = f
	f = e
	e = d + T1
	d = c
	c = b
	b = a
	a = T1 + T2

	return (a,b,c,d,e,f,g,h)
end

function loop(W, a, b, c, d ,e, f, g, h, leak::Function=(x,y)->x)
	for t in 0:63
		(a,b,c,d,e,f,g,h) = iteration(W[t+1],t,a,b,c,d,e,f,g,h,leak)
	end
	return (a,b,c,d,e,f,g,h)
end

function round(state::Sha256state, rnd::Int, leak::Function=(x,y)->x)
	# block is to be interpreted big endian
	W = calcW(state, map(state.decodefn, reinterpret(UInt32,state.block)))
	a = state.H[1+0]
	b = state.H[1+1]
	c = state.H[1+2]
	d = state.H[1+3]
	e = state.H[1+4]
	f = state.H[1+5]
	g = state.H[1+6]
	h = state.H[1+7]
	(a,b,c,d,e,f,g,h) = loop(W,a,b,c,d,e,f,g,h,leak)
	state.H[1+0] = a + state.H[1+0]
	state.H[1+1] = b + state.H[1+1]
	state.H[1+2] = c + state.H[1+2]
	state.H[1+3] = d + state.H[1+3]
	state.H[1+4] = e + state.H[1+4]
	state.H[1+5] = f + state.H[1+5]
	state.H[1+6] = g + state.H[1+6]
	state.H[1+7] = h + state.H[1+7]
end

function sha256(msg::AbstractVector{UInt8}, leak::Function=(x,y)->x)
	state = Sha256state()
	update(state, msg, leak)
	return final(state, leak)	
end

function hmacsha256(key::AbstractVector{UInt8}, msg::AbstractVector{UInt8})
	return hmac(Sha256state,key,msg)
end

export MD5state

mutable struct MD5state <: Shastate
	H::Vector{UInt32}
	block::Vector{UInt8}
	free::Int
	msgLen::Int
	rnd::Int
	decodefn::Function
	encodefn::Function
	MD5state() = new([SHA1H00, SHA1H01, SHA1H02, SHA1H03], zeros(UInt8, sha1blocksizebytes), sha1blocksizebytes, 0, 0,ltoh,htol)
end

# MD5 is Juliafied copy of ref implementation in:
# https://www.ietf.org/rfc/rfc1321.txt

const S11 = 7
const S12 = 12
const S13 = 17
const S14 = 22
const S21 = 5
const S22 = 9
const S23 = 14
const S24 = 20
const S31 = 4
const S32 = 11
const S33 = 16
const S34 = 23
const S41 = 6
const S42 = 10
const S43 = 15
const S44 = 21

F(x, y, z) = (((x) & (y)) | ((~x) & (z)))
G(x, y, z) = (((x) & (z)) | ((y) & (~z)))
H(x, y, z) = ((x) ⊻ (y) ⊻ (z))
I(x, y, z) = ((y) ⊻ ((x) | (~z)))

const ROTATE_LEFT = rotl

macro FF(a, b, c, d, x, s, ac)
   quote
	 ($(esc(a))) += F(($(esc(b))), ($(esc(c))), ($(esc(d)))) + ($(esc(x))) + ($(esc(ac)));
	 ($(esc(a))) = ROTATE_LEFT(($(esc(a))), ($(esc(s))));
	 ($(esc(a))) += ($(esc(b)));
   end
end

macro GG(a, b, c, d, x, s, ac)
	quote 
	 ($(esc(a))) += G(($(esc(b))), ($(esc(c))), ($(esc(d)))) + ($(esc(x))) + ($(esc(ac)));
	 ($(esc(a))) = ROTATE_LEFT(($(esc(a))), ($(esc(s))));
	 ($(esc(a))) += ($(esc(b)));
	end
end

macro HH(a, b, c, d, x, s, ac)
	quote
	 ($(esc(a))) += H(($(esc(b))), ($(esc(c))), ($(esc(d)))) + ($(esc(x))) + ($(esc(ac)));
	 ($(esc(a))) = ROTATE_LEFT(($(esc(a))), ($(esc(s))));
	 ($(esc(a))) += ($(esc(b)));
	end
end

macro II(a, b, c, d, x, s, ac)
	quote 
	 ($(esc(a))) += I(($(esc(b))), ($(esc(c))), ($(esc(d)))) + ($(esc(x))) + ($(esc(ac)));
	 ($(esc(a))) = ROTATE_LEFT(($(esc(a))), ($(esc(s))));
	 ($(esc(a))) += ($(esc(b)));
	end
end

function round(state::MD5state, rnd::Int, leak::Function=(x,y)->x)
  a = state.H[0+1]
  b = state.H[1+1]
  c = state.H[2+1]
  d = state.H[3+1]
  x = map(state.decodefn, reinterpret(UInt32,state.block))

  # Round 1 
  @FF(a, b, c, d, x[ 0+1], S11, 0xd76aa478); # 1 
  @FF(d, a, b, c, x[ 1+1], S12, 0xe8c7b756); # 2 
  @FF(c, d, a, b, x[ 2+1], S13, 0x242070db); # 3 
  @FF(b, c, d, a, x[ 3+1], S14, 0xc1bdceee); # 4 
  @FF(a, b, c, d, x[ 4+1], S11, 0xf57c0faf); # 5 
  @FF(d, a, b, c, x[ 5+1], S12, 0x4787c62a); # 6 
  @FF(c, d, a, b, x[ 6+1], S13, 0xa8304613); # 7 
  @FF(b, c, d, a, x[ 7+1], S14, 0xfd469501); # 8 
  @FF(a, b, c, d, x[ 8+1], S11, 0x698098d8); # 9 
  @FF(d, a, b, c, x[ 9+1], S12, 0x8b44f7af); # 10 
  @FF(c, d, a, b, x[10+1], S13, 0xffff5bb1); # 11 
  @FF(b, c, d, a, x[11+1], S14, 0x895cd7be); # 12 
  @FF(a, b, c, d, x[12+1], S11, 0x6b901122); # 13 
  @FF(d, a, b, c, x[13+1], S12, 0xfd987193); # 14 
  @FF(c, d, a, b, x[14+1], S13, 0xa679438e); # 15 
  @FF(b, c, d, a, x[15+1], S14, 0x49b40821); # 16 

 # Round 2 
  @GG(a, b, c, d, x[ 1+1], S21, 0xf61e2562); # 17 
  @GG(d, a, b, c, x[ 6+1], S22, 0xc040b340); # 18 
  @GG(c, d, a, b, x[11+1], S23, 0x265e5a51); # 19 
  @GG(b, c, d, a, x[ 0+1], S24, 0xe9b6c7aa); # 20 
  @GG(a, b, c, d, x[ 5+1], S21, 0xd62f105d); # 21 
  @GG(d, a, b, c, x[10+1], S22,  0x2441453); # 22 
  @GG(c, d, a, b, x[15+1], S23, 0xd8a1e681); # 23 
  @GG(b, c, d, a, x[ 4+1], S24, 0xe7d3fbc8); # 24 
  @GG(a, b, c, d, x[ 9+1], S21, 0x21e1cde6); # 25 
  @GG(d, a, b, c, x[14+1], S22, 0xc33707d6); # 26 
  @GG(c, d, a, b, x[ 3+1], S23, 0xf4d50d87); # 27 
  @GG(b, c, d, a, x[ 8+1], S24, 0x455a14ed); # 28 
  @GG(a, b, c, d, x[13+1], S21, 0xa9e3e905); # 29 
  @GG(d, a, b, c, x[ 2+1], S22, 0xfcefa3f8); # 30 
  @GG(c, d, a, b, x[ 7+1], S23, 0x676f02d9); # 31 
  @GG(b, c, d, a, x[12+1], S24, 0x8d2a4c8a); # 32 

  # Round 3 
  @HH(a, b, c, d, x[ 5+1], S31, 0xfffa3942); # 33 
  @HH(d, a, b, c, x[ 8+1], S32, 0x8771f681); # 34 
  @HH(c, d, a, b, x[11+1], S33, 0x6d9d6122); # 35 
  @HH(b, c, d, a, x[14+1], S34, 0xfde5380c); # 36 
  @HH(a, b, c, d, x[ 1+1], S31, 0xa4beea44); # 37 
  @HH(d, a, b, c, x[ 4+1], S32, 0x4bdecfa9); # 38 
  @HH(c, d, a, b, x[ 7+1], S33, 0xf6bb4b60); # 39 
  @HH(b, c, d, a, x[10+1], S34, 0xbebfbc70); # 40 
  @HH(a, b, c, d, x[13+1], S31, 0x289b7ec6); # 41 
  @HH(d, a, b, c, x[ 0+1], S32, 0xeaa127fa); # 42 
  @HH(c, d, a, b, x[ 3+1], S33, 0xd4ef3085); # 43 
  @HH(b, c, d, a, x[ 6+1], S34,  0x4881d05); # 44 
  @HH(a, b, c, d, x[ 9+1], S31, 0xd9d4d039); # 45 
  @HH(d, a, b, c, x[12+1], S32, 0xe6db99e5); # 46 
  @HH(c, d, a, b, x[15+1], S33, 0x1fa27cf8); # 47 
  @HH(b, c, d, a, x[ 2+1], S34, 0xc4ac5665); # 48 

  # Round 4 
  @II(a, b, c, d, x[ 0+1], S41, 0xf4292244); # 49 
  @II(d, a, b, c, x[ 7+1], S42, 0x432aff97); # 50 
  @II(c, d, a, b, x[14+1], S43, 0xab9423a7); # 51 
  @II(b, c, d, a, x[ 5+1], S44, 0xfc93a039); # 52 
  @II(a, b, c, d, x[12+1], S41, 0x655b59c3); # 53 
  @II(d, a, b, c, x[ 3+1], S42, 0x8f0ccc92); # 54 
  @II(c, d, a, b, x[10+1], S43, 0xffeff47d); # 55 
  @II(b, c, d, a, x[ 1+1], S44, 0x85845dd1); # 56 
  @II(a, b, c, d, x[ 8+1], S41, 0x6fa87e4f); # 57 
  @II(d, a, b, c, x[15+1], S42, 0xfe2ce6e0); # 58 
  @II(c, d, a, b, x[ 6+1], S43, 0xa3014314); # 59 
  @II(b, c, d, a, x[13+1], S44, 0x4e0811a1); # 60 
  @II(a, b, c, d, x[ 4+1], S41, 0xf7537e82); # 61 
  @II(d, a, b, c, x[11+1], S42, 0xbd3af235); # 62 
  @II(c, d, a, b, x[ 2+1], S43, 0x2ad7d2bb); # 63 
  @II(b, c, d, a, x[ 9+1], S44, 0xeb86d391); # 64 

  state.H[0+1] += a;
  state.H[1+1] += b;
  state.H[2+1] += c;
  state.H[3+1] += d;
end

export md5

function md5(msg::AbstractVector{UInt8}, leak::Function=(x,y)->x)
	state = MD5state()
	update(state, msg, leak)
	return final(state, leak)	
end

export hmacmd5

function hmacmd5(key::AbstractVector{UInt8}, msg::AbstractVector{UInt8})
	return hmac(MD5state,key,msg)
end
