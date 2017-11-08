using Base.Test

using Jlsca.Sca
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

	@test Sha.final(state) == expected
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

function shatest8()
	W = rand(UInt32)
	t = 0
	a0 = rand(UInt32)
	b0 = rand(UInt32)
	c0 = rand(UInt32)
	d0 = rand(UInt32)
	e0 = rand(UInt32)

	(a1,b1,c1,d1,e1) = Sha.iteration(W,t,a0,b0,c0,d0,e0)

	@test Sha.inviteration(W,t,a1,b1,c1,d1,e1) == (a0,b0,c0,d0,e0)
end

function sha256test1() 
	 @test sha256(b"abc") == hex2bytes("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD") 
end

function sha256test3()
	@test sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") == hex2bytes("248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1")
end


function hmacsha256test1()
    msg = b"Sample message for keylen<blocklen"
    key = hex2bytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    expected = hex2bytes("A28CF43130EE696A98F14A37678B56BCFCBDD9E5CF69717FECF5480F0EBDF790")
    out = hmacsha256(key, msg)

    @test expected == out
end

# FIXME move this out
function leak!(buf, str, state)
	# @printf("%s: %08x\n", str, state)
	write(buf, state)
	# write(buf, Sca.hw(state))
 #    for i in 0:3
 #        write(buf, Sca.hw((state >> i*8)&0xff))
 #    end
 #    for i in 0:7
 #        write(buf, Sca.hw((state >> i*4)&0xf))
 #    end
end

using ProgressMeter

# MOVE ME
function shatraces()
	samplesBuf = IOBuffer()
	nrOfSamples = 0
	nrOfTraces = 500
	local trs

    @showprogress for i in 1:nrOfTraces
    	input = [rand(UInt8) for i in 1:16]
        output = sha1(input, (x,y)->leak!(samplesBuf,x,y))

        if nrOfSamples == 0
            nrOfSamples = position(samplesBuf)
            filename = @sprintf("sha1.trs")
            trs = InspectorTrace(filename, 16+20, UInt8, nrOfSamples)
        else
            # sanity check
            if position(samplesBuf) != nrOfSamples
                @printf("WOWOOWOOOO!!! Cipher returns non-constant #samples/run\n")
                return
            end
        end

        trs[i] = ([input;output], takebuf_array(samplesBuf))

	end

	close(trs)
end

# MOVE ME
function sha256traces()
    samplesBuf = IOBuffer()
    nrOfSamples = 0
    nrOfTraces = 100
    local trs

    @showprogress for i in 1:nrOfTraces
        input = [rand(UInt8) for i in 1:16]
        output = sha256(input, (x,y)->leak!(samplesBuf,x,y))

        if nrOfSamples == 0
            nrOfSamples = position(samplesBuf)
            filename = @sprintf("sha256.trs")
            trs = InspectorTrace(filename, 16+32, UInt8, nrOfSamples)
        else
            # sanity check
            if position(samplesBuf) != nrOfSamples
                @printf("WOWOOWOOOO!!! Cipher returns non-constant #samples/run\n")
                return
            end
        end

        trs[i] = ([input;output], takebuf_array(samplesBuf))

    end

    close(trs)
end

function speedtest()
	state = [rand(UInt8) for i in 1:20]
	len = 100000

	for i in 1:len
		state = sha1(state)
	end
end

shatest1()
shatest2()
shatest3()
shatest4()
shatest5()
shatest6()
shatest7()
shatest8()

sha256test1()
sha256test3()
hmacsha256test1()

# @profile speedtest()
# Profile.print(maxdepth=12,combine=true)


# shatraces()
# sha256traces()
