# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Jlsca.Trs
using Jlsca.Aes
using ProgressMeter

const random = false
const nrOfTraces = 500
# random per trace
const prenoise = 10000
# random per trace set
const postnoise = 10000

if random
  testvec128 = hex2bytes("000102030405060708090a0b0c0d0e0f")
  testvec192 = hex2bytes("000102030405060708090a0b0c0d0e0f1011121314151617")
  testvec256 = hex2bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
else
  testvec128 = [UInt8(rand(0:255)) for i in 1:16]
  testvec192 = [UInt8(rand(0:255)) for i in 1:24]
  testvec256 = [UInt8(rand(0:255)) for i in 1:32]
end

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
    simulate(nrOfTraces, testvec128, Cipher)
end

function inputgenMC()
    r = rand(1:4)
    return [(i in [o for o in r:4:16] ? UInt8(rand(0:255)) : 0x0) for i in 1:16]
end

function simulateCipher128MC()
    simulate(nrOfTraces, testvec128, Cipher, inputgenMC, "mc")
end

function simulateInvCipher128MC()
    simulate(nrOfTraces, testvec128, InvCipher, inputgenMC, "mc")
end

function simulateEqInvCipher128MC()
    simulate(nrOfTraces, testvec128, EqInvCipher, inputgenMC, "mc")
end

function simulateCipher192()
    simulate(nrOfTraces, testvec192, Cipher)
end

function simulateCipher256()
    simulate(nrOfTraces, testvec256, Cipher)
end

function simulateInvCipher128()
    simulate(nrOfTraces, testvec128, InvCipher)
end

function simulateInvCipher192()
    simulate(nrOfTraces, testvec192, InvCipher)
end

function simulateInvCipher256()
    simulate(nrOfTraces, testvec256, InvCipher)
end

function simulateEqInvCipher128()
    simulate(nrOfTraces, testvec128, EqInvCipher)
end

function simulateEqInvCipher192()
    simulate(nrOfTraces, testvec192, EqInvCipher)
end

function simulateEqInvCipher256()
    simulate(nrOfTraces, testvec256, EqInvCipher)
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

    if cipher == Cipher
        mode = "ciph"
    elseif cipher == InvCipher
        mode = "invciph"
    elseif cipher == EqInvCipher
        mode = "eqinvciph"
    end

    local trs

    @showprogress for i in 1:nrOfTraces
        input = inputgen()
        rng = MersenneTwister(1)
				write(samplesBuf, [UInt8(rand(0:255)) for i in 1:prenoise])
        output = cipher(input, w, (x,y)->leak!(samplesBuf,x,y))
        write(samplesBuf, [UInt8(rand(rng, 0:255)) for i in 1:postnoise])

        if nrOfSamples == 0
            nrOfSamples = position(samplesBuf)
            filename = @sprintf("aes%d_%s_%s_%s.trs", kl*8, mc, mode, bytes2hex(key))
            trs = InspectorTrace(filename, 32, UInt8, nrOfSamples)
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
