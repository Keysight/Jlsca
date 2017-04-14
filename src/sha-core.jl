
export sha1,hmacsha1,sha1init,update,final

Ch(x::UInt32,y::UInt32,z::UInt32) = (x & y) $ (~x & z)
Maj(x::UInt32,y::UInt32,z::UInt32) = (x & y) $ (x & z) $ (y & z)
rotl(value::UInt32, count::Int) = (value<<count) | (value>>( (-count) & 0b11111 ))
rotr(value::UInt32, count::Int) = (value>>count) | (value<<( (-count) & 0b11111 ))
Parity(x::UInt32,y::UInt32,z::UInt32) = x $ y $ z

function f(t)
	if 0 <= t <= 19
		return Ch 
	elseif 20 <= t <= 39 || 60 <= t <= 79
		return Parity
	elseif 40 <= t <= 59
		return Maj
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

const H00 = UInt32(0x67452301)
const H01 = UInt32(0xefcdab89)
const H02 = UInt32(0x98badcfe)
const H03 = UInt32(0x10325476)
const H04 = UInt32(0xc3d2e1f0)

const sha1blocksizebytes = 64

type Sha1state 
	H0::UInt32
	H1::UInt32
	H2::UInt32
	H3::UInt32
	H4::UInt32
	block::Vector{UInt8}
	free::Int
	msgLen::Int

	Sha1state() = new(H00, H01, H02, H03, H04, zeros(UInt8, sha1blocksizebytes), sha1blocksizebytes, 0)
end

function calcW(Mi)
	W = zeros(UInt32, 80)

	for t in 1:16
		W[t] = Mi[t]
	end

	for t in 17:80
		W[t] = rotl(W[t-3] $ W[t-8] $ W[t-14] $ W[t-16], 1) 
	end

	return W
end 

function loop(W, a, b, c, d ,e)
	for t in 0:79
		T = rotl(a,5) + f(t)(b,c,d) + e + K(t) + W[t+1]
		e = d
		d = c
		c = rotl(b, 30)
		b = a
		a = T
	end
	return (a,b,c,d,e)
end

function round(state::Sha1state)
		# block is to be interpreted big endian
		W = calcW(map(ntoh, reinterpret(UInt32,state.block)))
		a = state.H0
		b = state.H1
		c = state.H2
		d = state.H3
		e = state.H4
		(a,b,c,d,e) = loop(W, a,b,c,d,e)
		state.H0 = a + state.H0
		state.H1 = b + state.H1
		state.H2 = c + state.H2
		state.H3 = d + state.H3
		state.H4 = e + state.H4
end

function update(state::Sha1state, msg::Vector{UInt8})

	# update the msg length
	state.msgLen += length(msg)

	msgOffset = 1

	while msgOffset <= length(msg)

		# fill up the block buffer
		bl = min(state.free, length(msg) - msgOffset + 1)
		blockOffset = length(state.block) - state.free + 1

		# @printf("bl %d, blockOffset %d, msgOffset %d\n", bl, blockOffset, msgOffset)
		state.block[blockOffset:(blockOffset + bl - 1)] = msg[msgOffset:(msgOffset + bl - 1)]
		msgOffset += bl
		state.free -= bl

		# flush if it's full
		if state.free == 0
			round(state)
			state.free = sha1blocksizebytes
		end
	end
end

function final(state::Sha1state)
	padlenBits = padlen(state.msgLen)
	paddedMsgLen = (padlenBits + 1 + 64) >> 3
	paddedMsg = zeros(UInt8, paddedMsgLen)	
	paddedMsg[1] = 0x80
	len64 = UInt64(state.msgLen*8)
	# @printf("len64 %d\n", len64)
	for i in 0:7
		paddedMsg[end-i] = ((len64 >> (i*8)) & 0xff)
	end

	update(state, paddedMsg)

	# there should be no residual data in state.block
	if state.free != sha1blocksizebytes
		throw(ErrorException("bad hat harry"))
	end

	# output is to be interpreted big endian
	return reinterpret(UInt8, map(hton, [state.H0,state.H1,state.H2,state.H3,state.H4]))
end

function sha1init()
	return Sha1state()
end

function sha1(msg::Vector{UInt8})
	state = sha1init()
	update(state, msg)
	return final(state)	
end

function K0(key::Vector{UInt8})
	if length(key) == sha1blocksizebytes
		return key
	elseif length(key) > sha1blocksizebytes
		hashed = sha1(key)
		return [hashed; [0x00 for i in 1:(sha1blocksizebytes - length(hashed))]]
	else
		return [key; [0x00 for i in 1:(sha1blocksizebytes - length(key))]]
	end
end

function hmacsha1(key::Vector{UInt8}, msg::Vector{UInt8})
	innerstate = sha1init()
	innerkey = K0(key) $ 0x36
	update(innerstate, innerkey)
	update(innerstate, msg)
	outerstate = sha1init()
	outerkey = K0(key) $ 0x5c
	update(outerstate, [outerkey; final(innerstate)])
	return final(outerstate)

end

