# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Jlsca.Sha

export Sha1InputAttack,Sha1OutputAttack

abstract type Sha1Attack <: Attack{UInt8} end

"""
The attack is the same as described in Section 3.4 in this [paper](https://link.springer.com/chapter/10.1007/978-3-319-25915-4_19) by Belaid and others.

We're going to take a look at SHA1 HMAC using the input. The key itself cannot be recovered since there is no differential data being mixed with the key. The two SHA1 states themselves are sufficient to create arbitrary HMACs. One can also attack the outer SHA1 using an output attack, but this is not shown here (although [Jlsca](https://github.com/Riscure/Jlsca) implements this attack too). We'll only be looking at the inner SHA1.

To explain this attack, we first define some terms:
* a0,b0,c0,d0,e0: the 160-bit SHA1 state we are to recover, in 5 32-bit numbers
* W0 - W3: the attacker controlled and known 32-bit inputs
* T0-T3: the value of T for rounds 0-3
* F0-F3: the output value of the F function for rounds 0-3
* Rot(x,a): rotates x left by a bits
* Ch(a,b,c) = (a & b) XOR (~a & c)

We then roll out first 4 rounds of the inner SHA1 loop in the terms defined above (constants omitted):
```
T0 = Rot(a0, 5) + Ch(b0, c0, d0) + e0 + W0
F0 = Ch(b0, c0, d0)

T1 = Rot(T0, 5) + Ch(a0, Rot(b0, 30), c0) + d0 + W1
F1 = Ch(a0, Rot(b0, 30), c0)

T2 = Rot(T1, 5) + Ch(T0, Rot(a0, 30), Rot(b0, 30)) + c0 + W2
F2 = Ch(T0, Rot(a0, 30), Rot(b0, 30))

T3 = Rot(T2, 5) + Ch(T1, Rot(T0, 30), Rot(a0, 30)) + Rot(b0, 30) + W3
F3 = Ch(T1, Rot(T0, 30), Rot(a0, 30))
```

The SHA1 input attack steps are then:
1. DPA attack on 32-bit modular addition to guess "Rot(a0, 5) + Ch(b0, c0, d0)" and predict "T0" since we know "W0" 
2. DPA attack on 32-bit modular addition to guess "Ch(a0, Rot(b0, 30), c0) + d0" and predict "T1" since we know "W1" and "Rot(T0, 5)" 
3. DPA attack on Ch function to guess "Rot(a0, 30)" and predict "F3" since we know "T1" and "Rot(T0, 30)" 
4. DPA attack on Ch function to guess "Rot(b0, 30)" and predict "F2" since we know "T0" and "Rot(a0, 30)"
5. DPA attack on 32-bit modular addition to guess "c0" and predict "T2" since we know "Rot(T1, 5) + Ch(T0, Rot(a0, 30), Rot(b0, 30))" and "W2" 

These 5 attacks allow us to recover the secret SHA1 state a0,b0,c0,d0,e0.  DPA attacks 1-5 are recovering 32-bit numbers and in order to enumerate the guesses we need to split the attacks up in smaller (typically 8-bits or less) attack so that the key space can be enumerated. How to split up the attacks is described in this [paper](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.94.7333&rep=rep1&type=pdf) by Lemke, Schramm and Paar. Note that DPA attack n depends on the output of attack n-1 for n > 1. In Jlsca terms we'd call these attack *phases*. For DPA 3 and 4 multiple parts of the secret can be recovered simulteaneously since they're independent. Within a *phase* you can therefore have multiple *targets*. 

In Jlsca, the SHA1 attack is split up in 14 phases and targets as follows:

* Phase 1, target 1: byte 0 of DPA 1
* Phase 2, target 1: byte 1 of DPA 1
* Phase 3, target 1: byte 2 of DPA 1
* Phase 4, target 1: byte 3 of DPA 1
* Phase 5, target 1: byte 0 of DPA 2
* Phase 6, target 1: byte 1 of DPA 2
* Phase 7, target 1: byte 2 of DPA 2
* Phase 8, target 1: byte 3 of DPA 2
* Phase 9, targets 1-4, 4 bytes of DPA 3
* Phase 10, targets 1-4, 4 bytes of DPA 4
* Phase 11, target 1: byte 0 of DPA 5
* Phase 12, target 1: byte 1 of DPA 5
* Phase 13, target 1: byte 2 of DPA 5
* Phase 14, target 1: byte 3 of DPA 5

Note also that this attack only uses the first 12 bytes of the input! (W0, W1 and W2)

Go see https://github.com/ikizhvatov/jlsca-tutorials/blob/master/hmacsha1pinata.ipynb for an application of this attack on a real target!!!
"""
mutable struct Sha1InputAttack <: Sha1Attack
  xor::Bool
  xorForT0::UInt32

  function Sha1InputAttack()
    return new(false, 0x00000000)
  end
end

mutable struct ModAdd <: Target{UInt8,UInt8,UInt8} end
target(a::ModAdd, data::UInt8, keyByte::UInt8) = data + keyByte
# target(a::ModAdd, data::UInt8, keyByte::UInt8) = UInt16(data) + keyByte
show(io::IO, a::ModAdd) = print(io, "Modular addition")
guesses(a::ModAdd) = collect(UInt8, 0:255)

mutable struct ModAddXor <: Target{UInt16,UInt8,UInt8} end
target(a::ModAddXor, data::UInt16, keyByte::UInt8) = (UInt8(data >> 8) + keyByte) ⊻ UInt8(data & 0xff)

guesses(a::ModAddXor) = collect(UInt8, 0:255)

mutable struct FoutZ4b <: Target{UInt8,UInt8,UInt8} end

function target(a::FoutZ4b, data::UInt8, keyByte::UInt8)  
    x = UInt8(data & 0xf)
    y = UInt8((data >> 4) & 0xf)
    return (((x & y) ⊻ (~x & keyByte)) & 0xf)
end

show(io::IO, a::FoutZ4b) = print(io, "Ch out, 4-bits in")
guesses(a::FoutZ4b) = collect(UInt8, 0:15)

mutable struct FoutZ16b <: Target{UInt16,UInt8,UInt8} end

function target(a::FoutZ16b, data::UInt16, keyByte::UInt8)
    x = UInt8(data & 0xff)
    y = UInt8((data >> 8) & 0xff)
    return (((x & y) ⊻ (~x & keyByte)) & 0xff)
end

show(io::IO, a::FoutZ16b) = print(io, "Ch out, 16-bits in")
guesses(a::FoutZ16b) = collect(UInt8, 0:255)

mutable struct FoutZ8b <: Target{UInt8,UInt8,UInt8} 
    y::UInt8
end

function target(a::FoutZ8b, x::UInt8, keyByte::UInt8)  
    return (((x & a.y) ⊻ (~x & keyByte)) & 0xff)
end

show(io::IO, a::FoutZ8b) = print(io, "Ch out, 8-bits in")
guesses(a::FoutZ8b) = collect(UInt8, 0:255)

# 0-based idx, big endian order
function setIntMSB(val::UInt32, idx::Int, data::AbstractVector{UInt8})
    data[idx*4+1:idx*4+4] = reinterpret(UInt8, [hton(val)])
end

W0(input::AbstractVector{UInt8}) = ntoh(reinterpret(UInt32, input[1:4])[1])
W1(input::AbstractVector{UInt8}) = ntoh(reinterpret(UInt32, input[5:8])[1])
W2(input::AbstractVector{UInt8}) = ntoh(reinterpret(UInt32, input[9:12])[1])
W3(input::AbstractVector{UInt8}) = ntoh(reinterpret(UInt32, input[13:16])[1])

R0(pi::AbstractVector{UInt8}) = ltoh(reinterpret(UInt32, pi[1:4])[1])
R1(pi::AbstractVector{UInt8}) = ltoh(reinterpret(UInt32, pi[5:8])[1])
a0rot(pi::AbstractVector{UInt8}) = ltoh(reinterpret(UInt32, pi[9:12])[1])

# nibblesfuck
# function a0rot(pi::AbstractVector{UInt8})
#     nibbles = pi[9:16]
#     ret::UInt32 = 0
#     for i in 8:-1:1
#         ret <<= 4
#         ret |= (nibbles[i] & 0xf)
#         # nibbles[i] <<= 4
#     end

#     return ret
# end

b0rot(pi::AbstractVector{UInt8}) = ltoh(reinterpret(UInt32, pi[13:16])[1])
R3(pi::AbstractVector{UInt8}) = ltoh(reinterpret(UInt32, pi[17:20])[1])

# data per row
function prepModAdd1(byteIdx::Int, key::UInt32, data::AbstractArray{UInt8}, initialXor::UInt32)
    d = W0(data)
    xor = initialXor

    ret::UInt8 = UInt8(((d + key) >> (byteIdx*8)) & 0xff)
    xorbyte::UInt8 = UInt8((xor >> (byteIdx*8)) & 0xff)

    ret16::UInt16 = (UInt16(ret) << 8) | xorbyte

    return ret16
end

# data per row
function prepModAdd2(byteIdx::Int, key::UInt32, data::AbstractArray{UInt8}, state::AbstractVector{UInt8})
    t0 = R0(state) + W0(data)
    xor = t0
    d = W1(data) + Sha.rotl(t0,5)

    ret::UInt8 = UInt8(((d + key) >> (byteIdx*8)) & 0xff)
    xorbyte::UInt8 = UInt8((xor >> (byteIdx*8)) & 0xff)

    ret16::UInt16 = (UInt16(ret) << 8) | xorbyte

    return ret16
end

function prepFoutZ3(data::AbstractArray{UInt8}, state::AbstractVector{UInt8})
    t0::UInt32 = R0(state) + W0(data)
    t0rot = Sha.rotl(t0,30)
    t1::UInt32 = Sha.rotl(t0, 5) + R1(state) + W1(data)
    ret = zeros(UInt16, 4)

    for i in 0:3
        shift = i*8
        idx = i+1
        ret[idx] = (t0rot >> shift) & 0xff
        ret[idx] <<= 8
        ret[idx] |= (t1 >> shift) & 0xff
    end
    return ret
end

function prepFoutZ4(data::AbstractArray{UInt8}, state::AbstractVector{UInt8})
    t0 = R0(state) + W0(data)

    return reinterpret(UInt8, [htol(t0)])
end

function prepModAdd5(byteIdx::Int, key::UInt32, data::AbstractArray{UInt8}, state::AbstractVector{UInt8})
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

function getDataPass(params::Sha1InputAttack, phase::Int, phaseInput::AbstractVector{UInt8})
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
    elseif intIdx == 3
        # DPA 4 
        # no XOR attack for this one!
        roundfn = x -> prepFoutZ4(x, phaseInput)
    elseif intIdx == 4
        # DPA 5
        if params.xor 
            roundfn = x -> [prepModAdd5(byteIdx, partialKey, x, phaseInput)]
        else
            roundfn = x -> [UInt8(prepModAdd5(byteIdx, partialKey, x, phaseInput) >> 8)]
        end
    end

    return roundfn
end

show(io::IO, a::Sha1InputAttack) = print(io, "Sha1 input")

function printParameters(params::Sha1InputAttack)
  @printf("T xor:        %s%s\n", string(params.xor), params.xor ? @sprintf(" (xor for T0 = %d)", params.xorForT0) : "")
end

function numberOfTargets(params::Sha1InputAttack, phase::Int)
    if (1 <= phase <= 8) || (11 <= phase <= 14)
        return 1
    elseif phase == 9
        return 4
    elseif phase == 10
        return 4
    end
end

function getTargets(params::Sha1InputAttack, phase::Int, phaseInput::AbstractVector{UInt8}) 
    if (1 <= phase <= 8) || (11 <= phase <= 14)
        if params.xor
            return [ModAddXor()]
        else
            return [ModAdd()]
        end
    elseif phase == 9
        return [FoutZ16b() for i in 1:4]
    elseif phase == 10
        a0r = a0rot(phaseInput)
        return [FoutZ8b((a0r >> ((i-1)*8)) & 0xff) for i in 1:4]
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

function correctKeyMaterial(params::Sha1InputAttack, knownKey::AbstractVector{UInt8})
    kk = map(ntoh, reinterpret(UInt32, knownKey))

    a0 = kk[1]
    b0 = kk[2]
    c0 = kk[3]
    d0 = kk[4]
    e0 = kk[5]

    res = Vector{UInt32}(undef,7)

    res[1] = e0 + Sha.rotl(a0,5) + Sha.Ch(b0,c0,d0) + Sha.K(0)
    res[2] = d0 + Sha.Ch(a0,Sha.rotl(b0,30),c0) + Sha.K(1)
    a0r = Sha.rotl(a0,30)
    res[3] = a0r
    # res[3] = 0
    # nibblesfuck
    # for i in 3:-1:0
    #     res[3] <<= 8
    #     res[3] |= ((a0r >> (i*4)) & 0xf)
    # end
    # res[4] = 0
    # for i in 7:-1:4
    #     res[4] <<= 8
    #     res[4] |= ((a0r >> (i*4)) & 0xf)
    # end
    b0r = Sha.rotl(b0,30)
    res[4] = b0r
    res[5] = c0 + Sha.K(2)

    return reinterpret(UInt8, map(htol, res))
end

function recoverKey(params::Sha1InputAttack, phaseInput::AbstractVector{UInt8})
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

mutable struct Sha1OutputAttack <: Sha1Attack end

mutable struct ModSub <: Target{UInt8,UInt8,UInt8} end
show(io::IO, a::ModSub) = print(io, "Modular subtraction")
target(a::ModSub, data::UInt8, keyByte::UInt8) = data - keyByte

numberOfPhases(params::Sha1OutputAttack) = 20
getTargets(params::Sha1OutputAttack, phase::Int, phaseInput::AbstractVector{UInt8}) = [ModSub()]
numberOfTargets(params::Sha1OutputAttack, phase::Int) = 1

function getDataPass(params::Sha1OutputAttack, phase::Int, phaseInput::AbstractVector{UInt8})
    byteIdx = (phase - 1) & 3
    intIdx = (phase - 1) >> 2

    partialKey = UInt32(0)
    if byteIdx > 0
        for i in (byteIdx-1):-1:0
            partialKey <<= 8
            partialKey |= phaseInput[intIdx*4+i+1]
        end
    end

    constPartialKey = partialKey

    roundfn = input -> (d = ntoh(reinterpret(UInt32, input[intIdx*4+1:intIdx*4+4])[1]); [UInt8(((d - constPartialKey) >> (byteIdx*8)) & 0xff)])

    return roundfn
end

function recoverKey(params::Sha1OutputAttack, phaseInput::AbstractVector{UInt8})
    return reinterpret(UInt8, map(bswap, reinterpret(UInt32, phaseInput)))
end

function correctKeyMaterial(params::Sha1OutputAttack, knownKey::AbstractVector{UInt8}, phase::Int)
    kk =  map(ntoh, reinterpret(UInt32, knownKey))

    byteIdx = (phase - 1) & 3
    intIdx = (phase - 1) >> 2

    return [UInt8((kk[intIdx+1] >> (byteIdx*8)) & 0xff)]
end

function correctKeyMaterial(params::Sha1OutputAttack, knownKey::AbstractVector{UInt8})
    kk =  map(ntoh, reinterpret(UInt32, knownKey))

    return reinterpret(UInt8, map(htol, kk))
end

show(io::IO, a::Sha1OutputAttack) = print(io, "Sha1 output")

# function printParameters(params::Sha1OutputAttack)
# end
