# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

# creates 123DES enc/dec simulation traces
#
# edit the constants to change how the traces are generated
# go to function calls at the bottom of this file to change which traces are generated

using Jlsca.Trs
using Jlsca.Des

# random key or static testkey
const random = false
# random per trace
const prenoise = 0
# random per trace set
const postnoise = 0
const nrOfTraces = 5000

if random
	testkey = map(x -> x & 0xfe, hex2bytes("0011223344556677"))
	testkey16 = map(x -> x & 0xfe, hex2bytes("00112233445566778899aabbccddeeff"))
	testkey24 = map(x -> x & 0xfe, hex2bytes("00112233445566778899aabbccddeeffdeadbeefcafecee5"))
else
	testkey = [UInt8(rand(0:255)) & 0xfe for i in 1:8]
	testkey16 = [UInt8(rand(0:255)) & 0xfe for i in 1:16]
	testkey24 = [UInt8(rand(0:255)) & 0xfe for i in 1:24]
end

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

		local trs

    for i in 1:nrOfTraces
				rng = MersenneTwister(1)
				write(samplesBuf, [UInt8(rand(0:255)) for i in 1:prenoise])
        input = inputgen()
        output = cipher(input, expkey, encrypt, (x,y)->leak!(samplesBuf,x,y))
				write(samplesBuf, [UInt8(rand(rng, 0:255)) for i in 1:postnoise])

        if nrOfSamples == 0
            nrOfSamples = position(samplesBuf)
						filename = @sprintf("%s_%s_%s.trs", ciphstr, mode, bytes2hex(key))
						trs = InspectorTrace(filename, 16, UInt8, nrOfSamples)
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

function simulateCipher()
    simulate(nrOfTraces, deskeyexpansion(testkey), testkey, des, true)
end

function simulateInvCipher()
	simulate(nrOfTraces, deskeyexpansion(testkey), testkey, des, false)
end


function simulateTDES1enc()
  simulate(nrOfTraces, tdes3keyexpansion(testkey), testkey, tdes3, true)
end

function simulateTDES1dec()
    simulate(nrOfTraces, tdes3keyexpansion(testkey), testkey, tdes3, false)
end


function simulateTDES2enc()
    simulate(nrOfTraces, tdes3keyexpansion(testkey16), testkey16, tdes3, true)
end

function simulateTDES2dec()
    simulate(nrOfTraces, tdes3keyexpansion(testkey16), testkey16, tdes3, false)
end


function simulateTDES3enc()
    simulate(nrOfTraces, tdes3keyexpansion(testkey24), testkey24, tdes3, true)
end

function simulateTDES3dec()
    simulate(nrOfTraces, tdes3keyexpansion(testkey24), testkey24, tdes3, false)
end

simulateCipher()
simulateInvCipher()
simulateTDES1enc()
simulateTDES1dec()
simulateTDES2enc()
simulateTDES2dec()
simulateTDES3enc()
simulateTDES3dec()
