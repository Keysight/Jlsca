# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using ..Aes
using ..Trs

import Base.show

export AesSboxAttack,AesMCAttack,AesKeyLength,AesMode

@enum AesMode CIPHER=1 INVCIPHER=2 EQINVCIPHER=3
@enum AesKeyLength KL128=16 KL192=24 KL256=32

for s in instances(AesMode); @eval export $(Symbol(s)); end
for s in instances(AesKeyLength); @eval export $(Symbol(s)); end

abstract type AesAttack <: Attack end

nrKeyByteValues(a::AesAttack) = 256
keyByteValues(a::AesAttack) = collect(UInt8,0:255)


# two types of attacks: sbox or mixcolumn
type AesSboxAttack <: AesAttack
  mode::AesMode
  keyLength::AesKeyLength
  direction::Direction
  dataOffset::Int
  keyByteOffsets::Vector{Int}
  knownKey::Nullable{Vector{UInt8}}
  analysis::Analysis
  xor::Bool
  updateInterval::Nullable{Int}
  phases::Vector{Int}
  phaseInput::Vector{UInt8}
  outputkka::Nullable{AbstractString}
  sbox::Vector{UInt8}
  invsbox::Vector{UInt8}

  function AesSboxAttack()
    leakageFunctions = [Bit(0), Bit(1), Bit(2), Bit(3), Bit(4), Bit(5), Bit(6), Bit(7)]
    return new(CIPHER, KL128, FORWARD, 1, collect(1:16), Nullable(), CPA(), false, Nullable(), [], Vector{UInt8}(0), Nullable(), Aes.sbox, Aes.invsbox)
  end
end

function getPhases(params::AesSboxAttack)
  if params.keyLength == KL128
    return [PHASE1]
  else
    return [PHASE1, PHASE2]
  end
end

type AesMCAttack <: AesAttack
  mode::AesMode
  keyLength::AesKeyLength
  direction::Direction
  dataOffset::Int
  keyByteOffsets::Vector{Int}
  knownKey::Nullable{Vector{UInt8}}
  analysis::Analysis
  xor::Bool
  updateInterval::Nullable{Int}
  phases::Vector{Int}
  phaseInput::Vector{UInt8}
  outputkka::Nullable{AbstractString}
  sbox::Vector{UInt8}
  invsbox::Vector{UInt8}

  function AesMCAttack()
    leakageFunctions = [Bit(0)]
    return new(CIPHER, KL128, FORWARD, 1, collect(1:16), Nullable(), CPA(), false, Nullable(), [], Vector{UInt8}(0), Nullable(), Aes.sbox, Aes.invsbox)
  end
end

function getPhases(params::AesMCAttack)
  return [PHASE1, PHASE2, PHASE3, PHASE4]
end


function toShortString(params::Union{AesSboxAttack,AesMCAttack})
  typeStr = (isa(params,AesSboxAttack) ? "SBOX" : "MC")
  modeStr = string(params.mode)
  lengthStr = string(params.keyLength)
  directionStr = string(params.direction)
  analysisStr = (isa(params.analysis, CPA) ? "CPA" : "LRA")

  return @sprintf("%s_%s_%s_%s_%s", typeStr, modeStr, lengthStr, analysisStr, directionStr)
 end

# target functions
type InvMcOut <: Target{UInt8,UInt32}
  invsbox::Vector{UInt8}
  constant::UInt8
  position::Int
end

function target(a::InvMcOut, x::UInt8, col::Int, keyByte::UInt8)
    mcIn = fill(a.constant, 4)
    mcIn[a.position] = a.invsbox[(x ⊻ keyByte) + 1]
    mcOut = Aes.InvMixColumn(mcIn)
    ret::UInt32 = 0
    for i in 1:4
      ret <<= 8
      ret |= mcOut[i]
    end
    return ret
end

show(io::IO, a::InvMcOut) = print(io, "Inverse MC out")


type McOut <: Target{UInt8,UInt32}
  sbox::Vector{UInt8}
  constant::UInt8
  position::Int
end

function target(a::McOut, x::UInt8, col::Int, keyByte::UInt8)
    mcIn = fill(a.constant, 4)
    mcIn[a.position] = a.sbox[(x ⊻ keyByte) + 1]
    mcOut = Aes.MixColumn(mcIn)
    ret::UInt32 = 0
    for i in 1:4
      ret <<= 8
      ret |= mcOut[i]
    end
    return ret
end

show(io::IO, a::McOut) = print(io, "MC out")

type McOutXORIn <: Target{UInt8,UInt32}
  sbox::Vector{UInt8}
  constant::UInt8
  position::Int
end

function target(a::McOutXORIn, x::UInt8, col::Int, keyByte::UInt8)
    mcIn = fill(constant, 4)
    mcIn[a.position] = a.sbox[(x ⊻ keyByte) + 1]
    mcOut = Aes.MixColumn(mcIn) ⊻ mcIn
    ret::UInt32 = 0
    for i in 1:4
      ret <<= 8
      ret |= mcOut[i]
    end
    return ret
end

show(io::IO, a::McOutXORIn) = print(io, "Inverse MC out, XOR'ed w/ input")

type SboxOut <: Target{UInt8,UInt8}
  sbox::Vector{UInt8}
end

target(a::SboxOut, data::UInt8, col::Int, keyByte::UInt8) = a.sbox[(data ⊻ keyByte) + 1]
show(io::IO, a::SboxOut) = print(io, "Sbox out")

type InvSboxOut <: Target{UInt8,UInt8}
  invsbox::Vector{UInt8}
end

target(a::InvSboxOut, data::UInt8, col::Int, keyByte::UInt8) = a.invsbox[(data ⊻ keyByte) + 1]
show(io::IO, a::InvSboxOut) = print(io, "Inverse sbox out")

type SboxOutXORIn <: Target{UInt8,UInt8}
  sbox::Vector{UInt8}
end

target(a::SboxOutXORIn, data::UInt8, col::Int, keyByte::UInt8) = data ⊻ keyByte ⊻ a.sbox[(data ⊻ keyByte) + 1]
show(io::IO, a::SboxOutXORIn) = print(io, "Sbox out, xor'ed w/ input")

type InvSboxOutXORIn <: Target{UInt8,UInt8}
  sbox::Vector{UInt8}
end

target(a::InvSboxOutXORIn, data::UInt8, col::Int, keyByte::UInt8) =  data ⊻ keyByte ⊻ a.invsbox[(data ⊻ keyByte) + 1]
show(io::IO, a::InvSboxOutXORIn) = print(io, "Inverse Sbox out, xor'ed w/ input")

# some round functions
function invRound(output::Matrix, roundkey::Matrix)
    state = Aes.AddRoundKey(output, roundkey)
    state = Aes.InvShiftRows(state)
    state = Aes.InvSubBytes(state)
    state = Aes.InvMixColumns(state)
    return state
end

function round(output::Matrix, roundkey::Matrix)
    state = Aes.AddRoundKey(output, roundkey)
    state = Aes.SubBytes(state)
    state = Aes.ShiftRows(state)
    state = Aes.MixColumns(state)
    return state
end

# run the key schedule backwards to recover a key
function recoverKey(keymaterial::Vector{UInt8}, mode, direction)
  if (mode == CIPHER && direction == FORWARD) || (mode == INVCIPHER && direction == BACKWARD) || (mode == EQINVCIPHER && direction == BACKWARD)
      return keymaterial
    else
      Nk = div(length(keymaterial),Aes.wz)
      Nr = Aes.keylength2Nr(length(keymaterial))
      w = Aes.KeyExpansionBackwards(keymaterial, Nr, Nk)
      return w[1:Nk*Aes.wz]
    end
end

function recoverKey(params::AesSboxAttack, phaseInput::Vector{UInt8})
  mode = params.mode
  direction = params.direction

  if params.keyLength == KL128
    key = recoverKey(phaseInput, mode, direction)
  else
    secondrklen = length(params.keyByteOffsets)
    # for these mode & direction combinations we actually recovered a InvMixColumn key, so correct it
    if (mode == CIPHER && direction == BACKWARD) || (mode == INVCIPHER && direction == FORWARD) || (mode == EQINVCIPHER && direction == FORWARD)
      for i in 1:div(secondrklen,4)
        phaseInput[16+(i-1)*4+1:16+i*4] = Aes.MixColumn(phaseInput[16+(i-1)*4+1:16+i*4])
      end
    end

    # put the recovered key material in the correct order and run the key schedules
    if (direction == BACKWARD && mode == CIPHER) || (direction == FORWARD && mode != CIPHER)
        keymaterial = vcat(phaseInput[16+1:16+secondrklen], phaseInput[1:16])
    else
        keymaterial = vcat(phaseInput[1:16], phaseInput[16+1:16+secondrklen])
    end

    key = recoverKey(keymaterial, mode, direction)
  end

  return key
end

function recoverKey(params::AesMCAttack, phaseInput::Vector{UInt8}) 
  mode = params.mode
  direction = params.direction

  reordered = Vector{UInt8}(16)
  for i in 0:3
    reordered[i*4+1:i*4+4] = phaseInput[[o for o in i+1:4:16]]
  end
  return recoverKey(reordered, mode, direction)
end

function getNumberOfCandidates(params::AesAttack)
  return 256
end

function getTarget(params::AesMCAttack)
  if (params.direction == FORWARD && params.mode == CIPHER) || (params.direction == BACKWARD && params.mode != CIPHER)
    if params.xor
      targetfn = McOutXORIn(params.sbox, 0x0, 1)
    else
      targetfn = McOut(params.sbox, 0x0, 1)
    end
  else
    if params.xor
      targetfn = InvMcOutXORIn(params.invsbox, 0x0, 1)
    else
      targetfn = InvMcOut(params.invsbox, 0x0, 1)
    end
  end

  return targetfn
end


function getTarget(params::AesSboxAttack)
  if (params.direction == FORWARD && params.mode == CIPHER) || (params.direction == BACKWARD && params.mode != CIPHER)
    if params.xor
      targetfn = SboxOutXORIn(params.sbox)
    else
      targetfn = SboxOut(params.sbox)
    end
  else
    if params.xor
      targetfn = InvSboxOutXORIn(params.invsbox)
    else
      targetfn = InvSboxOut(params.invsbox)
    end
  end

  return targetfn
end


function printParameters(params::Union{AesSboxAttack,AesMCAttack})
  target = getTarget(params)

  attackStr = (isa(params, AesSboxAttack) ? "Sbox" : "Mixcolumn")
  analysisStr = string(typeof(params.analysis).name.name)

  @printf("AES %s %s attack parameters\n", attackStr, analysisStr)
  printParameters(params.analysis)
  @printf("mode:       %s\n", string(params.mode))
  @printf("key length: %s\n", string(params.keyLength))
  @printf("direction:  %s\n", string(params.direction))
  @printf("target:     %s\n", string(target))
  @printf("data at:    %s\n", string(params.dataOffset))
  @printf("key bytes:  %s\n", string(params.keyByteOffsets))
  if !isnull(params.knownKey)
    @printf("known key:  %s\n", bytes2hex(get(params.knownKey)))
  end
end


# get the round key material the attack is recovering to add known key information in the scoring
function getCorrectRoundKeyMaterial(params::AesAttack, phase::Int)
  if isnull(params.knownKey)
    return Vector{UInt8}(0)
  end

  mode = params.mode
  direction = params.direction
  knownKey = get(params.knownKey)
  keyLength = params.keyLength

  rklength = 16
  off = 0
  if isa(params, AesSboxAttack)
    if phase == PHASE1
      off = 0
    else phase == PHASE2
      off = 16
      if keyLength == KL192
        rklength = 8
      end
    end
  end

  if (mode == CIPHER && direction == FORWARD) || (mode == INVCIPHER && direction == BACKWARD) || (mode == EQINVCIPHER && direction == BACKWARD)
    roundkey = knownKey[off+1:off+rklength]
  else
    Nk = div(length(knownKey),Aes.wz)
    Nr = Aes.keylength2Nr(length(knownKey))
    w = Aes.KeyExpansion(knownKey, Nr, Nk)
    roundkey = w[end-off+1-rklength:end-off]
  end

  if isa(params, AesSboxAttack) && phase == PHASE2
    if (mode == CIPHER && direction == BACKWARD) || (mode == INVCIPHER && direction == FORWARD) || (mode == EQINVCIPHER && direction == FORWARD)
      for i in 1:div(rklength,4)
        roundkey[(i-1)*4+1:i*4] = Aes.InvMixColumn(roundkey[(i-1)*4+1:i*4])
      end
    end
  end

  if isa(params, AesMCAttack)
    return Nullable{Vector{UInt8}}(roundkey[[o for o in phase:4:16]])
  else
    return Nullable{Vector{UInt8}}(roundkey)
  end
end

# filter function for mixcolumns attack so that we don't accept data that's not semi-constant
function filterConstantInput(offsets, data::Vector{UInt8}, constant::UInt8)
  for i in 1:length(data)
    if !(i in offsets)
      if data[i] != constant
        # return nothing (and thus reject the trace)
        return Vector{UInt8}(0)
      end
    end
  end
  return [data[x] for x in offsets]
end

# the mixcolumns attack
function scatask(super::Task, trs::Trace, params::AesMCAttack, firstTrace=1, numberOfTraces=length(trs), phase::Int=PHASE1, phaseInput=Vector{UInt8}(0))
  params.keyLength == KL128 || throw(ErrorException("AesMCAttack only supported for 128 bits keys"))
  params.direction == FORWARD || throw(ErrorException("AesMCAttack only supported in FORWARD direction"))

  mode = params.mode
  keyLength = params.keyLength
  direction = params.direction
  # dataOffsets = params.dataOffsets
  knownKey = params.knownKey
  target = getTarget(params)

  local scores

  # select the bytes we need
  addDataPass(trs, (x -> x[params.dataOffset + params.keyByteOffsets - 1]))

  # should make this configurable maybe, but doesn't affect the attack (even if constant doesn't match the one in the traces)
  constant = 0x0

  if keyLength != KL128
    throw(Exception("Only KL128 supported for MC attack"))
  end

  # myfn = (data,keyBytePosition,keyVal) -> target(params, data, keyBytePosition, keyVal, 1, constant)


  if phase == PHASE1
    offset = 1
  elseif phase == PHASE2
    offset = 2
  elseif phase == PHASE3
    offset = 3
  elseif phase == PHASE4
    offset = 4
  end

  offsets = [o for o in offset:4:16]

  # select only the traces we want
  addDataPass(trs, x -> filterConstantInput(offsets, x, constant))

  # do the attack
  scores = analysis(super, params, phase, trs, firstTrace, numberOfTraces, target, offsets)

  popDataPass(trs)
  popDataPass(trs)

  if scores == nothing
    @printf("No results .. probably means your input traces are not chosen input\n");
    return nothing
  end

  # get the recovered key material
  roundkey::Vector{UInt8} = getRoundKey(scores)
  yieldto(super, (PHASERESULT, roundkey))

  if phase == PHASE4
    yieldto(super, (FINISHED,nothing))
  else
  end

end


function getRoundFunction(phase::Int, params::AesSboxAttack, phaseInput::Vector{UInt8})
  if phase == PHASE2 && params.keyLength != KL128
      if params.keyLength == KL192
        dataWidth = 8
      else
        dataWidth = 16
      end

    # setup the round function to calculate the output or input of the next target round
    if (params.mode == CIPHER && params.direction == BACKWARD) || (params.mode == INVCIPHER && params.direction == FORWARD) || (params.mode == EQINVCIPHER && params.direction == FORWARD)
        roundfn_ = x -> invRound(reshape(x, (4,4)), reshape(phaseInput, (4,4)))[end-dataWidth+1:end]
      else
        roundfn_ = x -> round(reshape(x, (4,4)), reshape(phaseInput, (4,4)))[1:dataWidth]
    end
    roundfn = Nullable(roundfn_)
  else
    roundfn = Nullable()
  end

  return roundfn
end

# the sbox attack
function scatask(super::Task, trs::Trace, params::AesSboxAttack, firstTrace=1, numberOfTraces=length(trs), phase::Int=PHASE1, phaseInput=Vector{UInt8}(0))
  mode = params.mode
  keyLength = params.keyLength
  direction = params.direction
  # dataOffsets = params.dataOffsets
  knownKey = params.knownKey
  updateInterval = params.updateInterval
  target = getTarget(params)


  local key, scores

  # FIXME: implement caching of cond avg traces
  # if isfile("hack.bin")
  #   fd = open("hack.bin", "r")
  #   (data,samples) = deserialize(fd)
  #   close(fd)
  # else
  #   @time (data,samples) = readTraces(trs, firstTrace, numberOfTraces)
  #   if typeof(samples) == Vector{Matrix}
  #     fd = open("hack.bin", "w")
  #     serialize(fd, (data,samples))
  #     # samples = map(s-> s[:,361:361+552], samples)
  #     close(fd)
  #   end
  # end

  addDataPass(trs, (x -> x[params.dataOffset + collect(1:16) - 1]))

  roundfn = getRoundFunction(phase, params, phaseInput)

  if !isnull(roundfn)
    addDataPass(trs, get(roundfn))
  end

  notAllKeyBytes::Bool = (phase == PHASE1 && length(params.keyByteOffsets) < 16) || (phase == PHASE2 && keyLength == KL256 && length(params.keyByteOffsets) < 16) || (phase == PHASE2 && keyLength == KL192 && length(params.keyByteOffsets) < 8)

  # if the client doesn't want all the key bytes, we won't give him all the key bytes ;)
  if notAllKeyBytes
    addDataPass(trs, (x -> x[params.keyByteOffsets]))
  end

  # do the attack
  scores = analysis(super, params, phase, trs, firstTrace, numberOfTraces, target, params.keyByteOffsets)

  # if we added a round function on the input data, now we need to remove it
  if !isnull(roundfn)
    popDataPass(trs)
  end

  # if the client didn't want all the key bytes, we need to pop another pass
  if notAllKeyBytes
    popDataPass(trs)
  end

  # pop the pass we used to select the bytes we need
  popDataPass(trs)

  if notAllKeyBytes
    # not enough key bytes to continue
    return
  end

  # get the recovered key material
  roundkey::Vector{UInt8} = getRoundKey(scores)
  yieldto(super, (PHASERESULT, roundkey))

  if phase == PHASE1 && keyLength == KL128
    yieldto(super, (FINISHED,nothing))
  elseif phase == PHASE1
    # FIXME: get rid of this hack
    if keyLength == KL192
      params.keyByteOffsets = collect(1:8)
    else
      params.keyByteOffsets = collect(1:16)
    end
  elseif phase == PHASE2
    yieldto(super, (FINISHED,nothing))
  end
end
