# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

include("aes.jl")
include("conditional.jl")
include("trs.jl")
include("sca-leakages.jl")

using Trs
using Aes

const random = true
const nrOfTraces = 500
const extrasamples = 0
testvec128 = hex2bytes("000102030405060708090a0b0c0d0e0f")
testvec192 = hex2bytes("000102030405060708090a0b0c0d0e0f1011121314151617")
testvec256 = hex2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

function leak!(buf, str, state)
    # don't leak the actual key schedule
    if !endswith(str, "k_sch")
    # if endswith(str, "m_col")
        write(buf, vec(state))
        write(buf, hw(state))
        # write(buf, hw32(state))
    end

    return state
end

function simulateCipher128()
    if random
        key = [UInt8(rand(0:255)) for i in 1:16]
    else
        key = testvec128
    end

    simulate(nrOfTraces, key, Cipher)
end

function inputgenMC()
    r = rand(1:4)
    return [(i in [o for o in r:4:16] ? UInt8(rand(0:255)) : 0x0) for i in 1:16]
end

function simulateCipher128MC()
    if random
        key = [UInt8(rand(0:255)) for i in 1:16]
    else
        key = testvec128
    end

    simulate(nrOfTraces, key, Cipher, inputgenMC, "mc")
end

function simulateInvCipher128MC()
    if random
        key = [UInt8(rand(0:255)) for i in 1:16]
    else
        key = testvec128
    end

    simulate(nrOfTraces, key, InvCipher, inputgenMC, "mc")
end

function simulateEqInvCipher128MC()
    if random
        key = [UInt8(rand(0:255)) for i in 1:16]
    else
        key = testvec128
    end

    simulate(nrOfTraces, key, EqInvCipher, inputgenMC, "mc")
end

function simulateCipher192()
    if random
        key = [UInt8(rand(0:255)) for i in 1:24]
    else
        key = testvec192
    end

    simulate(nrOfTraces, key, Cipher)
end

function simulateCipher256()
    if random
        key = [UInt8(rand(0:255)) for i in 1:32]
    else
        key = testvec256
    end

    simulate(nrOfTraces, key, Cipher)
end

function simulateInvCipher128()
    if random
        key = [UInt8(rand(0:255)) for i in 1:16]
    else
        key = testvec128
    end

    simulate(nrOfTraces, key, InvCipher)
end

function simulateInvCipher192()
    if random
        key = [UInt8(rand(0:255)) for i in 1:24]
    else
        key = testvec192
    end

    simulate(nrOfTraces, key, InvCipher)
end


function simulateInvCipher256()
    if random
        key = [UInt8(rand(0:255)) for i in 1:32]
    else
        key = testvec256
    end

    simulate(nrOfTraces, key, InvCipher)
end

function simulateEqInvCipher128()
    if random
        key = [UInt8(rand(0:255)) for i in 1:16]
    else
        key = testvec128
    end

    simulate(nrOfTraces, key, EqInvCipher)
end

function simulateEqInvCipher192()
    if random
        key = [UInt8(rand(0:255)) for i in 1:24]
    else
        key = testvec192
    end

    simulate(nrOfTraces, key, EqInvCipher)
end

function simulateEqInvCipher256()
    if random
        key = [UInt8(rand(0:255)) for i in 1:32]
    else
        key = testvec256
    end

    simulate(nrOfTraces, key, EqInvCipher)
end

function simulate(nrOfTraces, key, cipher, inputgen=() -> [UInt8(rand(0:255)) for i in 1:16], mc="sb")
    kl = length(key)
    if cipher == Cipher || cipher == InvCipher
        keyexpansion = KeyExpansion
    else
        keyexpansion = EqInvKeyExpansion
    end

    w = keyexpansion(key, keylength2Nr(kl), div(kl,4))

    samplesBuf = IOBuffer()

    nrOfSamples = 0
    samples = Union
    data = Union

    for i in 1:nrOfTraces
        input = inputgen()
        # input = hex2bytes(replace(" 00112233445566778899aabbccddeeff", " ", ""))
        # input = hex2bytes(replace("8ea2b7ca516745bfeafc49904b496089 ", " ", ""))

        output = cipher(input, w, (x,y)->leak!(samplesBuf,x,y))

        if nrOfSamples == 0
            nrOfSamples = position(samplesBuf) + extrasamples
            samples = zeros(UInt8, (nrOfTraces, nrOfSamples))
            data = zeros(UInt8, (nrOfTraces, 32))
        else
            # sanity check
            if position(samplesBuf) != nrOfSamples - extrasamples
                @printf("WOWOOWOOOO!!! Cipher returns non-constant #samples/run\n")
                return
            end
        end

        samples[i,:] = [takebuf_array(samplesBuf); [UInt8(rand(0:255)) for i in 1:extrasamples]]
        data[i,1:16] = input
        data[i,17:32] = output

    end

    if cipher == Cipher
        mode = "ciph"
    elseif cipher == InvCipher
        mode = "invciph"
    elseif cipher == EqInvCipher
        mode = "eqinvciph"
    end

    writeToTraces(@sprintf("aes%d_%s_%s_%s.trs", kl*8, mc, mode, bytes2hex(key)), data, samples)
end

simulateCipher128MC()
simulateInvCipher128MC()
simulateEqInvCipher128MC()
simulateCipher128()
simulateCipher192()
simulateCipher256()
simulateInvCipher128()
simulateInvCipher192()
simulateInvCipher256()
simulateEqInvCipher128()
simulateEqInvCipher192()
simulateEqInvCipher256()
