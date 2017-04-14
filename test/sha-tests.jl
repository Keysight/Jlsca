using Base.Test


using Jlsca.Sha
using Jlsca.Trs

function shatest1()
	@test sha1(b"abc") == hex2bytes("a9993e364706816aba3e25717850c26c9cd0d89d")
end

function shatest2()
	@test sha1(b"") == hex2bytes("da39a3ee5e6b4b0d3255bfef95601890afd80709")
end

function shatest3()
	@test sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") == hex2bytes("84983e441c3bd26ebaae4aa1f95129e5e54670f1")
end

function shatest4()
	expected = hex2bytes("34aa973cd4c4daa4f61eeb2bdbad27316534016f")

	state = sha1init()

	for i in 1:1000000
		update(state, b"a")
	end

	@test final(state) == expected
end

function shatest5() 
	@test hmacsha1(hex2bytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"), b"Sample message for keylen=blocklen") == hex2bytes("5FD596EE78D5553C8FF4E72D266DFD192366DA29")
end

function shatest6()
	msg = b"Sample message for keylen<blocklen"
	key = hex2bytes("000102030405060708090A0B0C0D0E0F10111213")
	expected = hex2bytes("4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807")
	out = hmacsha1(key, msg)

	@test expected == out
end

function shatest7()
	msg = b"Sample message for keylen<blocklen, with truncated tag"
	key = hex2bytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30") 
	expected = hex2bytes("FE3529565CD8E28C5FA79EAC")
	out = hmacsha1(key, msg)

	@test expected == out[1:12]
end

function shatestmodaddBits() 
	secret::UInt32 = 0xdeadbeef
	traces = 1000
	samples = zeros(UInt8, traces, 32)
	data = zeros(UInt8, traces, 4)

	for i in 1:traces
		r = rand(UInt32)
		a = secret + r
		for j in 1:32
			samples[i,j] = ((a >> (j-1)) & 1)
		end
		for j in 1:4
			# big endian
			data[i,4-j+1] = ((r >> ((j-1)*8)) & 0xff)
		end
	end

	writeToTraces("modaddBits.trs", data, samples)
end

function shatestmodaddHw8() 
	secret::UInt32 = 0xc335ba47
	traces = 1000
	samples = zeros(UInt8, traces, 4)
	data = zeros(UInt8, traces, 4)

	for i in 1:traces
		r = rand(UInt32)
		a = secret + r
		for j in 1:4
			samples[i,j] = hw((a >> ((j-1)*8)) & 0xff)
		end
		for j in 1:4
			# big endian
			data[i,4-j+1] = ((r >> ((j-1)*8)) & 0xff)
		end
	end

	writeToTraces("modaddHw8.trs", data, samples)
end

function shatestmodaddHw32() 
	secret::UInt32 = 0xb4b3c4f3
	traces = 1000
	samples = zeros(UInt8, traces, 1)
	data = zeros(UInt8, traces, 4)

	for i in 1:traces
		r = rand(UInt32)
		a = secret + r
		samples[i,1] = hw(a)
		for j in 1:4
			# big endian
			data[i,4-j+1] = ((r >> ((j-1)*8)) & 0xff)
		end
	end

	writeToTraces("modaddHw32.trs", data, samples)
end

function shatestmodaddmadness()
	secret::UInt32 = 0xdeadb000
	traces = 10

	for i in 1:traces
		r = rand(UInt32)
		a = secret + r
		b::UInt8 = r & 0xff
		k1::UInt8 = 0x4f
		k2::UInt8 = k1 | 0x80
		@printf("%08x + %08x == %08x\n", secret, r, secret+r)
		@printf("%02x + %02x == %02x %s\n", b, k1, b + k1, bits(b + k1))
		@printf("%02x + %02x == %02x %s\n", b, k2, b + k2, bits(b + k2))
	end

end

shatest1()
shatest2()
shatest3()
shatest4()
shatest5()
shatest6()
shatest7()

