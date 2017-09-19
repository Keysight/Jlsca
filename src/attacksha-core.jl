# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Jlsca.Sha

export Sha1InputAttack,Sha1OutputAttack,getCorrectRoundKeyMaterial

# 0-based idx, big endian order
function getIntMSB(idx::Int, data::Vector{UInt8})
    return ntoh(reinterpret(UInt32, data[idx*4+1:idx*4+4])[1])
end

# 0-based idx, big endian order
function setIntMSB(val::UInt32, idx::Int, data::Vector{UInt8})
    data[idx*4+1:idx*4+4] = reinterpret(UInt8, [hton(val)])
end

# 0-based idx, little endian order
function getInt(idx::Int, data::Vector{UInt8})
    return ltoh(reinterpret(UInt32, data[idx*4+1:idx*4+4])[1])
end

# data per row
function prepModAdd(intIdx::Int, byteIdx::Int, state::Vector{UInt8}, key::UInt32, data::Array{UInt8}, initialXor::UInt32=0x00000000)
    d::UInt32 = 0

    # remove the input variables not under attack 
    if intIdx == 0
        d = getIntMSB(intIdx, data)
        xor = initialXor
    elseif intIdx == 1
        t0 = getInt(0, state) + getIntMSB(0, data)
        xor = t0
        d = getIntMSB(intIdx, data) + Sha.rotl(t0,5)
    elseif intIdx == 4
        t0 = getInt(0, state) + getIntMSB(0, data)
        t1 = Sha.rotl(t0, 5) + getInt(1, state) + getIntMSB(1, data)
        xor = t1
        a0rot = getInt(2,state)
        b0rot = getInt(3,state)
        d = Sha.rotl(t1,5) + Sha.Ch(t0,a0rot,b0rot) + getIntMSB(2,data)
    end

	ret::UInt8 = UInt8(((d + key) >> (byteIdx*8)) & 0xff)
    xorbyte::UInt8 = UInt8((xor >> (byteIdx*8)) & 0xff)


    ret16::UInt16 = (UInt16(ret) << 8) | xorbyte

    return ret16
end

type ModAdd <: Target{UInt8,UInt8}
end

target(a::ModAdd, data::UInt8, col::Int, keyByte::UInt8) = data + keyByte

type ModAddXor <: Target{UInt16,UInt8}
end

target(a::ModAddXor, data::UInt16, col::Int, keyByte::UInt8) = (UInt8(data >> 8) + keyByte) ⊻ UInt8(data & 0xff)

function prepFoutZ(intIdx::Int, state::Vector{UInt8}, data::Array{UInt8})

    # remove the input variables not under attack 
    if intIdx == 2
        t0::UInt32 = getInt(0, state) + getIntMSB(0, data)
        t0rot = Sha.rotl(t0,30)
        t1::UInt32 = Sha.rotl(t0, 5) + getInt(1, state) + getIntMSB(1, data)
        ret = zeros(UInt16, 4)
        for i in 1:4
            shift = (i-1)*8
            ret[i] = (t0rot >> shift) & 0xff
            ret[i] <<= 8
            ret[i] |= (t1 >> shift) & 0xff
        end
        return ret
    elseif intIdx == 3
        t0 = getInt(0, state) + getIntMSB(0, data)
        a0rot = getInt(2,state)

        ret = zeros(UInt16, 4)
        for i in 1:4
            shift = (i-1)*8
            ret[i] = (a0rot >> shift) & 0xff
            ret[i] <<= 8
            ret[i] |= (t0 >> shift) & 0xff
        end
        return ret
    else
        throw(ErrorException("noooooo"))
    end
end

type FoutZ <: Target{UInt16,UInt8}
end

function target(a::FoutZ, data::UInt16, col::Int, keyByte::UInt8)  
    x = data & 0xff
    y = (data >> 8) & 0xff
    return ((x & y) ⊻ (~x & keyByte))
end

abstract type Sha1Attack <: Attack end

type Sha1InputAttack <: Sha1Attack
  knownKey::Nullable{Vector{UInt8}}
  analysis::Analysis
  updateInterval::Nullable{Int}
  phases::Vector{Int}
  phaseInput::Vector{UInt8}
  outputkka::Nullable{AbstractString}
  dataOffset::Int
  xor::Bool
  xorForT0::UInt32

  function Sha1InputAttack()
    return new(Nullable(), CPA(), Nullable(), collect(1:14), Vector{UInt8}(0), Nullable(), 1, false, 0)
  end
end

nrKeyByteValues(a::Sha1Attack) = 256
keyByteValues(a::Sha1Attack) = collect(UInt8,0:255)

function printParameters(params::Sha1InputAttack)
  @printf("SHA1 input attack parameters\n")
  printParameters(params.analysis)
  @printf("input at:   %s\n", string(params.dataOffset))
  if !isnull(params.knownKey)
    @printf("known key:  %s\n", bytes2hex(get(params.knownKey)))
  end
end

function getIdxes(params::Sha1InputAttack, phase::Int)
    if 1 <= phase <= 8
        intIdx = div(phase-1,4)
        byteIdx = (phase-1) % 4
        nrBytes = 1
    elseif phase == 9 
        intIdx = 2
        byteIdx = 0
        nrBytes = 4
    elseif phase == 10
        intIdx = 3
        byteIdx = 0
        nrBytes = 4
    elseif 11 <= phase <= 14
        intIdx = 4
        byteIdx = (phase-11) % 4
        nrBytes = 1
    end

    return (intIdx,byteIdx,nrBytes)
end

function getCorrectRoundKeyMaterial(params::Sha1InputAttack, phase::Int)
    kk = get(params.knownKey)

    (intIdx,byteIdx,nrBytes) = getIdxes(params,phase)

    a0 = getIntMSB(0,kk)
    b0 = getIntMSB(1,kk)
    c0 = getIntMSB(2,kk)
    d0 = getIntMSB(3,kk)
    e0 = getIntMSB(4,kk)

    res = Vector{UInt32}(5)

    res[1] = e0 + Sha.rotl(a0,5) + Sha.Ch(b0,c0,d0) + Sha.K(0)
    res[2] = d0 + Sha.Ch(a0,Sha.rotl(b0,30),c0) + Sha.K(1)
    res[3] = Sha.rotl(a0,30)
    res[4] = Sha.rotl(b0,30)
    res[5] = c0 + Sha.K(2)

    return reinterpret(UInt8, map(htol, res))[intIdx*4+byteIdx+1:intIdx*4+byteIdx+nrBytes]

end

function scatask(super::Task, trs::Trace, params::Sha1InputAttack, firstTrace=1, numberOfTraces=length(trs), phase::Int=PHASE1, phaseInput=Vector{UInt8}(0))
    (intIdx,byteIdx,nrBytes) = getIdxes(params,phase)

    addDataPass(trs, (x -> x[params.dataOffset + collect(1:16) - 1]))

    if (1 <= phase <= 8) || (11 <= phase <= 14)
        partialKey = UInt32(0)
        if byteIdx > 0
            for i in (byteIdx-1):-1:0
                partialKey <<= 8
                partialKey |= phaseInput[intIdx*4+i+1]
            end
        end

        if params.xor 
            addDataPass(trs, x -> [prepModAdd(intIdx, byteIdx, phaseInput, partialKey, x, params.xorForT0)])
            target = ModAddXor()
        else
            addDataPass(trs, x -> [UInt8(prepModAdd(intIdx, byteIdx, phaseInput, partialKey, x) >> 8)])
            target = ModAdd()
        end
            
        # gets one byte at a time
        kbs = [intIdx*4+byteIdx+1] 
    elseif 9 <= phase <= 10         
        # gets 4 bytes in one go
        addDataPass(trs, x -> prepFoutZ(intIdx, phaseInput, x))
        target = FoutZ()
        kbs = collect(intIdx*4+1:intIdx*4+4)
    end


    scores = analysis(super,params, phase, trs, firstTrace, numberOfTraces, target, kbs)
    rk = getRoundKey(scores)

    popDataPass(trs)

    popDataPass(trs)

    yieldto(super, (PHASERESULT, rk)) 

    if phase == 14
        yieldto(super, (FINISHED,nothing))
    end
end

function recoverKey(params::Sha1InputAttack, phaseInput::Vector{UInt8})
    state = zeros(UInt8, 20)
    a0 = Sha.rotr(getInt(2,phaseInput), 30)
    b0 = Sha.rotr(getInt(3,phaseInput), 30)
    c0 = getInt(4,phaseInput) - Sha.K(2)
    d0 = getInt(1,phaseInput) - Sha.Ch(a0,Sha.rotl(b0,30),c0) - Sha.K(1)
    e0 = getInt(0,phaseInput) - Sha.rotl(a0,5) - Sha.Ch(b0,c0,d0) - Sha.K(0)
    setIntMSB(a0, 0, state)
    setIntMSB(b0, 1, state)
    setIntMSB(c0, 2, state)
    setIntMSB(d0, 3, state)
    setIntMSB(e0, 4, state)
    return state
end

function getNumberOfCandidates(params::Sha1InputAttack)
	return 256
end

type Sha1OutputAttack <: Sha1Attack
  knownKey::Nullable{Vector{UInt8}}
  analysis::Analysis
  updateInterval::Nullable{Int}
  phases::Vector{Int}
  phaseInput::Vector{UInt8}
  outputkka::Nullable{AbstractString}
  dataOffset::Int

  function Sha1OutputAttack()
    return new(Nullable(), CPA(), Nullable(), collect(1:20), Vector{UInt8}(0), Nullable(), 1)
  end
end

# data per row
function prepModSub(intIdx::Int, byteIdx::Int, state::Vector{UInt8}, key::UInt32, data::Array{UInt8})
    d::UInt32 = getIntMSB(intIdx, data)

    # add the partial result and return the byte we're attacking
    ret::UInt8 = UInt8(((d - key) >> (byteIdx*8)) & 0xff)

    return [ret]
end

type ModSub <: Target{UInt8,UInt8}
end

target(a::ModSub, data::UInt8, col::Int, keyByte::UInt8) = data - keyByte

function getIdxes(params::Sha1OutputAttack, phase::Int)
    intIdx = div(phase-1,4)
    byteIdx = (phase-1) % 4

    return (intIdx,byteIdx)
end

function scatask(super::Task, trs::Trace, params::Sha1OutputAttack, firstTrace=1, numberOfTraces=length(trs), phase::Int=PHASE1, phaseInput=Vector{UInt8}(0))
    addDataPass(trs, (x -> x[params.dataOffset + collect(1:20) - 1]))

    (intIdx,byteIdx) = getIdxes(params,phase)

    partialKey = UInt32(0)
    if byteIdx > 0
        for i in (byteIdx-1):-1:0
            partialKey <<= 8
            partialKey |= phaseInput[intIdx*4+i+1]
        end
    end

    addDataPass(trs, x -> prepModSub(intIdx, byteIdx, phaseInput, partialKey, x))
 
    target = ModSub()
    kbs = [intIdx*4+byteIdx+1] 

    scores = analysis(super,params, phase, trs, firstTrace, numberOfTraces, target, kbs)
    rk = getRoundKey(scores)

    popDataPass(trs)

    popDataPass(trs)
    
    yieldto(super, (PHASERESULT, rk))

    if phase == 20
        yieldto(super, (FINISHED,nothing))
    end
end

function recoverKey(params::Sha1OutputAttack, phaseInput::Vector{UInt8})
    return reinterpret(UInt8, map(bswap, reinterpret(UInt32, phaseInput)))
end

function getCorrectRoundKeyMaterial(params::Sha1OutputAttack, phase::Int)
    kk = get(params.knownKey)

    (intIdx,byteIdx) = getIdxes(params,phase)

    return [UInt8((getIntMSB(intIdx,kk) >> (byteIdx*8)) & 0xff)]
end

function printParameters(params::Sha1OutputAttack)
  @printf("SHA1 output attack parameters\n")
  printParameters(params.analysis)
  @printf("output at:  %s\n", string(params.dataOffset))
  if !isnull(params.knownKey)
    @printf("known key:  %s\n", bytes2hex(get(params.knownKey)))
  end
end
