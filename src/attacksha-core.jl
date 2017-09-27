# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Jlsca.Sha

export Sha1InputAttack,Sha1OutputAttack

abstract type Sha1Attack <: Attack end

type Sha1InputAttack <: Sha1Attack
  xor::Bool
  xorForT0::UInt32

  function Sha1InputAttack()
    return new(false, 0x00000000)
  end
end

type ModAdd <: Target{UInt8,UInt8} end
target(a::ModAdd, data::UInt8, keyByte::UInt8) = data + keyByte

guesses(a::ModAdd) = collect(UInt8, 0:255)

type ModAddXor <: Target{UInt16,UInt8} end
target(a::ModAddXor, data::UInt16, keyByte::UInt8) = (UInt8(data >> 8) + keyByte) ⊻ UInt8(data & 0xff)

guesses(a::ModAddXor) = collect(UInt8, 0:255)

type FoutZ <: Target{UInt8,UInt8} end
function target(a::FoutZ, data::UInt8, keyByte::UInt8)  
    x = data & 0xf
    y = (data >> 4) & 0xf
    return ((x & y) ⊻ (~x & keyByte))
end

guesses(a::FoutZ) = collect(UInt8, 0:15)

# 0-based idx, big endian order
function setIntMSB(val::UInt32, idx::Int, data::Vector{UInt8})
    data[idx*4+1:idx*4+4] = reinterpret(UInt8, [hton(val)])
end

W0(input::Vector{UInt8}) = ntoh(reinterpret(UInt32, input[1:4])[1])
W1(input::Vector{UInt8}) = ntoh(reinterpret(UInt32, input[5:8])[1])
W2(input::Vector{UInt8}) = ntoh(reinterpret(UInt32, input[9:12])[1])
W3(input::Vector{UInt8}) = ntoh(reinterpret(UInt32, input[13:16])[1])

R0(pi::Vector{UInt8}) = ltoh(reinterpret(UInt32, pi[1:4])[1])
R1(pi::Vector{UInt8}) = ltoh(reinterpret(UInt32, pi[5:8])[1])

function a0rot(pi::Vector{UInt8})
    nibbles = pi[9:16]
    ret::UInt32 = 0
    for i in 8:-1:1
        ret <<= 4
        ret |= (nibbles[i] & 0xf)
        nibbles[i] <<= 4
    end

    return ret
end

function b0rot(pi::Vector{UInt8})
    nibbles = pi[17:24]
    ret::UInt32 = 0
    for i in 8:-1:1
        ret <<= 4
        ret |= (nibbles[i] & 0xf)
        nibbles[i] <<= 4
    end

    return ret
end

R3(pi::Vector{UInt8}) = ltoh(reinterpret(UInt32, pi[25:28])[1])

# data per row
function prepModAdd1(byteIdx::Int, key::UInt32, data::Array{UInt8}, initialXor::UInt32)
    d = W0(data)
    xor = initialXor

    ret::UInt8 = UInt8(((d + key) >> (byteIdx*8)) & 0xff)
    xorbyte::UInt8 = UInt8((xor >> (byteIdx*8)) & 0xff)

    ret16::UInt16 = (UInt16(ret) << 8) | xorbyte

    return ret16
end

# data per row
function prepModAdd2(byteIdx::Int, key::UInt32, data::Array{UInt8}, state::Vector{UInt8})
    t0 = R0(state) + W0(data)
    xor = t0
    d = W1(data) + Sha.rotl(t0,5)

    ret::UInt8 = UInt8(((d + key) >> (byteIdx*8)) & 0xff)
    xorbyte::UInt8 = UInt8((xor >> (byteIdx*8)) & 0xff)

    ret16::UInt16 = (UInt16(ret) << 8) | xorbyte

    return ret16
end

function prepFoutZ3(data::Array{UInt8}, state::Vector{UInt8})
    t0::UInt32 = R0(state) + W0(data)
    t0rot = Sha.rotl(t0,30)
    t1::UInt32 = Sha.rotl(t0, 5) + R1(state) + W1(data)
    ret = zeros(UInt8, 8)

    for i in 0:7
        shift = i*4
        idx = i
        ret[idx+1] = (t0rot >> shift) & 0xf
        ret[idx+1] <<= 4
        ret[idx+1] |= (t1 >> shift) & 0xf
    end
    return ret
end

function prepFoutZ4(data::Array{UInt8}, state::Vector{UInt8})
    t0 = R0(state) + W0(data)
    a0r = a0rot(state)

    ret = zeros(UInt8, 8)

    for i in 0:7
        shift = i*4
        idx = i
        ret[idx+1] = (a0r >> shift) & 0xf
        ret[idx+1] <<= 4
        ret[idx+1] |= (t0 >> shift) & 0xf
    end
    return ret
end

function prepModAdd5(byteIdx::Int, key::UInt32, data::Array{UInt8}, state::Vector{UInt8})
    d::UInt32 = 0

    t0 = R0(state) + W0(data)
    t1 = Sha.rotl(t0, 5) + R1(state) + W1(data)
    xor = t1
    a0r = a0rot(state)
    b0r = b0rot(state)
    d = Sha.rotl(t1,5) + Sha.Ch(t0,a0r,b0r) + W2(data)

    ret::UInt8 = UInt8(((d + key) >> (byteIdx*8)) & 0xff)
    xorbyte::UInt8 = UInt8((xor >> (byteIdx*8)) & 0xff)


    ret16::UInt16 = (UInt16(ret) << 8) | xorbyte

    return ret16
end

function getDataPass(params::Sha1InputAttack, phase::Int, phaseInput::Vector{UInt8})
    o = offsetIntoPhaseInput(params, phase)
    byteIdx = o & 3
    intIdx = o >> 2

    partialKey = UInt32(0)
    if byteIdx > 0
        for i in (byteIdx-1):-1:0
            partialKey <<= 8
            partialKey |= phaseInput[intIdx*4+i+1]
        end
    end
    
    if intIdx == 0
        # DPA 1 
        if params.xor 
            roundfn = x -> [prepModAdd1(byteIdx, partialKey, x, params.xorForT0)]
        else
            roundfn = x -> [UInt8(prepModAdd1(byteIdx, partialKey, x, params.xorForT0) >> 8)]
        end
    elseif intIdx == 1
        # DPA 2
        if params.xor 
            roundfn = x -> [prepModAdd2(byteIdx, partialKey, x, phaseInput)]
        else
            roundfn = x -> [UInt8(prepModAdd2(byteIdx, partialKey, x, phaseInput) >> 8)]
        end
    elseif intIdx == 2
        # DPA 3 
        # no XOR attack for this one!
        roundfn = x -> prepFoutZ3(x, phaseInput)
    elseif intIdx == 4
        # DPA 4 
        # no XOR attack for this one!
        roundfn = x -> prepFoutZ4(x, phaseInput)
    elseif intIdx == 6
        # DPA 5
        if params.xor 
            roundfn = x -> [prepModAdd5(byteIdx, partialKey, x, phaseInput)]
        else
            roundfn = x -> [UInt8(prepModAdd5(byteIdx, partialKey, x, phaseInput) >> 8)]
        end
    end

    return Nullable(roundfn)
end

function printParameters(params::Sha1InputAttack)
  @printf("SHA1 input attack parameters\n")
  @printf("T xor:      %s%s\n", string(params.xor), params.xor ? @sprintf(" (xor for T0 = %d)", params.xorForT0) : "")
end

function getTarget(params::Sha1InputAttack, phase::Int, targetOffset::Int) 
    if (1 <= phase <= 8) || (11 <= phase <= 14)
        if params.xor
            return ModAddXor()
        else
            return ModAdd()
        end
    else
        return FoutZ()
    end
end

function numberOfTargets(params::Sha1InputAttack, phase::Int)
    if (1 <= phase <= 8) || (11 <= phase <= 14)
        return 1
    else
        return 8
    end
end

numberOfPhases(params::Sha1InputAttack) = 14

function offsetIntoPhaseInput(params::Sha1Attack, phase::Int)
    if phase > 1
        offset = sum(x -> numberOfTargets(params, x), 1:(phase-1))
    else
        offset = 0
    end

    return offset
end

function correctKeyMaterial(params::Sha1InputAttack, knownKey::Vector{UInt8})
    kk = map(ntoh, reinterpret(UInt32, knownKey))

    a0 = kk[1]
    b0 = kk[2]
    c0 = kk[3]
    d0 = kk[4]
    e0 = kk[5]

    res = Vector{UInt32}(7)

    res[1] = e0 + Sha.rotl(a0,5) + Sha.Ch(b0,c0,d0) + Sha.K(0)
    res[2] = d0 + Sha.Ch(a0,Sha.rotl(b0,30),c0) + Sha.K(1)
    a0r = Sha.rotl(a0,30)
    res[3] = 0
    for i in 3:-1:0
        res[3] <<= 8
        res[3] |= ((a0r >> i*4) & 0xf)
    end
    for i in 7:-1:4
        res[4] <<= 8
        res[4] |= ((a0r >> i*4) & 0xf)
    end
    b0r = Sha.rotl(b0,30)
    res[5] = 0
    for i in 3:-1:0
        res[5] <<= 8
        res[5] |= ((b0r >> i*4) & 0xf)
    end
    res[6] = 0
    for i in 7:-1:4
        res[6] <<= 8
        res[6] |= ((b0r >> i*4) & 0xf)
    end
    res[7] = c0 + Sha.K(2)

    return reinterpret(UInt8, map(htol, res))
end

function recoverKey(params::Sha1InputAttack, phaseInput::Vector{UInt8})
    state = zeros(UInt8, 20)
    a0 = Sha.rotr(a0rot(phaseInput), 30)
    b0 = Sha.rotr(b0rot(phaseInput), 30)
    c0 = R3(phaseInput) - Sha.K(2)
    d0 = R1(phaseInput) - Sha.Ch(a0,Sha.rotl(b0,30),c0) - Sha.K(1)
    e0 = R0(phaseInput) - Sha.rotl(a0,5) - Sha.Ch(b0,c0,d0) - Sha.K(0)
    setIntMSB(a0, 0, state)
    setIntMSB(b0, 1, state)
    setIntMSB(c0, 2, state)
    setIntMSB(d0, 3, state)
    setIntMSB(e0, 4, state)
    return state
end

type Sha1OutputAttack <: Sha1Attack end

type ModSub <: Target{UInt8,UInt8} end
target(a::ModSub, data::UInt8, keyByte::UInt8) = data - keyByte

numberOfPhases(params::Sha1OutputAttack) = 20
getTarget(params::Sha1OutputAttack, phase::Int, targetOffset::Int) = ModSub()
numberOfTargets(params::Sha1OutputAttack, phase::Int) = 1

function getDataPass(params::Sha1OutputAttack, phase::Int, phaseInput::Vector{UInt8})
    byteIdx = (phase - 1) & 3
    intIdx = (phase - 1) >> 2

    partialKey = UInt32(0)
    if byteIdx > 0
        for i in (byteIdx-1):-1:0
            partialKey <<= 8
            partialKey |= phaseInput[intIdx*4+i+1]
        end
    end

    const constPartialKey = partialKey

    roundfn = input -> (d = ntoh(reinterpret(UInt32, input[intIdx*4+1:intIdx*4+4])[1]); [UInt8(((d - constPartialKey) >> (byteIdx*8)) & 0xff)])

    return Nullable(roundfn)
end

function recoverKey(params::Sha1OutputAttack, phaseInput::Vector{UInt8})
    return reinterpret(UInt8, map(bswap, reinterpret(UInt32, phaseInput)))
end

function correctKeyMaterial(params::Sha1OutputAttack, knownKey::Vector{UInt8}, phase::Int)
    kk =  map(ntoh, reinterpret(UInt32, knownKey))

    byteIdx = (phase - 1) & 3
    intIdx = (phase - 1) >> 2

    return [UInt8((kk[intIdx+1] >> (byteIdx*8)) & 0xff)]
end

function correctKeyMaterial(params::Sha1OutputAttack, knownKey::Vector{UInt8})
    kk =  map(ntoh, reinterpret(UInt32, knownKey))

    return reinterpret(UInt8, map(htol, kk))
end

function printParameters(params::Sha1OutputAttack)
  @printf("SHA1 output attack parameters\n")
end
