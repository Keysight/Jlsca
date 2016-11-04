# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

include("des.jl")
include("conditional.jl")
include("trs.jl")
include("sca-leakages.jl")

using Trs
using Des

const random = true
testkey = hex2bytes("0001020304050607")

function leak!(buf, str, state)
	if isa(state, BitVector)
        write(buf, toBytes(state))
        write(buf, hw(toNibbles(state)))
    else
        write(buf, state)
        write(buf, hw(state))
    end

    return state
end

function deskeyexpansion(key)
    return KeyExpansion(key)
end

function des(input, expkey, encrypt, leakfn)
    return Cipher(input, expkey, leakfn, encrypt)
end

function tdes3keyexpansion(key)
    if length(key) == 24
        return (KeyExpansion(key[1:8]), KeyExpansion(key[9:16]), KeyExpansion(key[17:24]))
    elseif length(key) == 16
        return (KeyExpansion(key[1:8]), KeyExpansion(key[9:16]), KeyExpansion(key[1:8]))
    elseif length(key) == 8
        return (KeyExpansion(key), KeyExpansion(key), KeyExpansion(key))
    end
end

function tdes3(input, expkeys, encrypt, leakfn)
    if encrypt
        fn = TDESencrypt
    else
        fn = TDESdecrypt
    end

    return fn(input, expkeys[1], expkeys[2], expkeys[3], leakfn)
end

function simulate(nrOfTraces, expkey, key, cipher, encrypt, inputgen=() -> [UInt8(rand(0:255)) for i in 1:8])
    samplesBuf = IOBuffer()

    nrOfSamples = 0
    samples = Union
    data = Union

    for i in 1:nrOfTraces
        input = inputgen()
        output = cipher(input, expkey, encrypt, (x,y)->leak!(samplesBuf,x,y))

        if nrOfSamples == 0
            nrOfSamples = position(samplesBuf)
            samples = zeros(UInt8, (nrOfTraces, nrOfSamples))
            data = zeros(UInt8, (nrOfTraces, 16))
        else
            # sanity check
            if position(samplesBuf) != nrOfSamples
                @printf("WOWOOWOOOO!!! Cipher returns non-constant #samples/run\n")
                return
            end
        end

        samples[i,:] = takebuf_array(samplesBuf)
        data[i,1:8] = input
        data[i,9:16] = output
    end

    if encrypt
        mode = "enc"
    else
        mode = "dec"
    end

    if cipher == des
        ciphstr = "des"
    else
        ciphstr = @sprintf("tdes%d", div(length(key),8))
    end

    writeToTraces(@sprintf("%s_%s_%s.trs", ciphstr, mode, bytes2hex(key)), data, samples)
end

function simulateCipher()
    nrOfTraces = 500
    if random
        key = [UInt8(rand(0:255))&0xfe for i in 1:8]
    else
        key = testkey
    end

    simulate(nrOfTraces, deskeyexpansion(key), key, des, true)
end

function simulateInvCipher()
    nrOfTraces = 500
    if random
        key = [UInt8(rand(0:255))&0xfe for i in 1:8]
    else
        key = testkey
    end

    simulate(nrOfTraces, deskeyexpansion(key), key, des, false)
end


function simulateTDES1enc()
    nrOfTraces = 500
    if random
        key = [UInt8(rand(0:255))&0xfe for i in 1:8]
    else
        key = testkey
    end

    simulate(nrOfTraces, tdes3keyexpansion(key), key, tdes3, true)
end

function simulateTDES1dec()
    nrOfTraces = 500
    if random
        key = [UInt8(rand(0:255))&0xfe for i in 1:8]
    else
        key = testkey
    end

    simulate(nrOfTraces, tdes3keyexpansion(key), key, tdes3, false)
end


function simulateTDES2enc()
    nrOfTraces = 500
    if random
        key = [UInt8(rand(0:255))&0xfe for i in 1:16]
    else
        key = testkey
    end

    simulate(nrOfTraces, tdes3keyexpansion(key), key, tdes3, true)
end

function simulateTDES2dec()
    nrOfTraces = 500
    if random
        key = [UInt8(rand(0:255))&0xfe for i in 1:16]
    else
        key = testkey
    end

    simulate(nrOfTraces, tdes3keyexpansion(key), key, tdes3, false)
end


function simulateTDES3enc()
    nrOfTraces = 500
    if random
        key = [UInt8(rand(0:255))&0xfe for i in 1:24]
    else
        key = testkey
    end

    simulate(nrOfTraces, tdes3keyexpansion(key), key, tdes3, true)
end

function simulateTDES3dec()
    nrOfTraces = 500
    if random
        key = [UInt8(rand(0:255))&0xfe for i in 1:24]
    else
        key = testkey
    end

    simulate(nrOfTraces, tdes3keyexpansion(key), key, tdes3, false)
end

simulateCipher()
simulateInvCipher()
simulateTDES1enc()
simulateTDES1dec()
simulateTDES2enc()
simulateTDES2dec()
simulateTDES3enc()
simulateTDES3dec()
