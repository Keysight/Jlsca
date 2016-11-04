# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Aes
using Trs
using ProgressMeter

@enum AesMode CIPHER=1 INVCIPHER=2 EQINVCIPHER=3
@enum AesKeyLength KL128=16 KL192=24 KL256=32

abstract AesAttack <: Attack

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
  phases::Vector{Phase}
  phaseInput::Nullable{Vector{UInt8}}
  outputkka::Nullable{AbstractString}

  function AesSboxAttack()
    leakageFunctions = [bit0, bit1, bit2, bit3, bit4, bit5, bit6, bit7]
    return new(CIPHER, KL128, FORWARD, 1, collect(1:16), Nullable(), DPA(), false, Nullable(), [], Nullable(), Nullable())
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
  phases::Vector{Phase}
  phaseInput::Nullable{Vector{UInt8}}
  outputkka::Nullable{AbstractString}

  function AesMCAttack()
    leakageFunctions = [bit0]
    return new(CIPHER, KL128, FORWARD, 1, collect(1:16), Nullable(), DPA(), false, Nullable(), [], Nullable(), Nullable())
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
  analysisStr = (isa(params.analysis, DPA) ? "DPA" : "LRA")

  return @sprintf("%s_%s_%s_%s_%s", typeStr, modeStr, lengthStr, analysisStr, directionStr)
 end

# target functions
function invMcOut(x::UInt8, keyByte::UInt8, position::Int, constant::UInt8)
    mcIn = fill(constant, 4)
    mcIn[position] = invsbox[(x $ keyByte) + 1]
    mcOut = Aes.InvMixColumn(mcIn)
    ret::UInt32 = 0
    for i in 1:4
      ret <<= 8
      ret |= mcOut[i]
    end
    return ret
end

function invMcOut(data::Array{UInt8}, dataColumn, keyByte::UInt8, position::Int, constant::UInt8)
    ret = map(x -> invMcOut(x,keyByte,position,constant), data)
    return ret
end


function mcOut(x::UInt8, keyByte::UInt8, position::Int, constant::UInt8)
    mcIn = fill(constant, 4)
    mcIn[position] = sbox[(x $ keyByte) + 1]
    mcOut = Aes.MixColumn(mcIn)
    ret::UInt32 = 0
    for i in 1:4
      ret <<= 8
      ret |= mcOut[i]
    end
    return ret
end

function mcOut(data::Array{UInt8}, dataColumn, keyByte::UInt8, position::Int, constant::UInt8)
    ret = map(x -> mcOut(x,keyByte,position,constant), data)
    return ret
end

function mcOutXORIn(x::UInt8, keyByte::UInt8, position::Int, constant::UInt8)
    mcIn = fill(constant, 4)
    mcIn[position] = sbox[(x $ keyByte) + 1]
    mcOut = Aes.MixColumn(mcIn) $ mcIn
    ret::UInt32 = 0
    for i in 1:4
      ret <<= 8
      ret |= mcOut[i]
    end
    return ret
end

function mcOutXORIn(data::Array{UInt8}, dataColumn, keyByte::UInt8, position::Int, constant::UInt8)
    ret = map(x -> mcOutXORIn(x,keyByte,position,constant), data)
    return ret
end

function sboxOut(data::Array{UInt8}, dataColumn, keyByte::UInt8)
    ret = map(x -> sbox[(x $ keyByte) + 1], data)
    return ret
end

function invSboxOut(data::Array{UInt8}, dataColumn, keyByte::UInt8)
    ret = map(x -> invsbox[(x $ keyByte) + 1], data)
    return ret
end

function sboxOutXORIn(data::Array{UInt8}, dataColumn, keyByte::UInt8)
    ret = map(x -> x $ keyByte $ sbox[(x $ keyByte) + 1], data)
    return ret
end

function invSboxOutXORIn(data::Array{UInt8}, dataColumn, keyByte::UInt8)
    ret = map(x -> x $ keyByte $ invsbox[(x $ keyByte) + 1], data)
    return ret
end


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

function getNumberOfAverages(params::AesAttack)
  return 256
end

function getTargetFunction(params::AesMCAttack)
  if (params.direction == FORWARD && params.mode == CIPHER) || (params.direction == BACKWARD && params.mode != CIPHER)
    if params.xor
      targetfn = mcOutXORIn
    else
      targetfn = mcOut
    end
  else
    if params.xor
      targetfn = invMcOutXORIn
    else
      targetfn = invMcOut
    end
  end

  return targetfn
end


function getTargetFunction(params::AesSboxAttack)
  if (params.direction == FORWARD && params.mode == CIPHER) || (params.direction == BACKWARD && params.mode != CIPHER)
    if params.xor
      targetfn = sboxOutXORIn
    else
      targetfn = sboxOut
    end
  else
    if params.xor
      targetfn = invSboxOutXORIn
    else
      targetfn = invSboxOut
    end
  end

  return targetfn
end


function printParameters(params::Union{AesSboxAttack,AesMCAttack})
  targetFunction = getTargetFunction(params)

  attackStr = (isa(params, AesSboxAttack) ? "Sbox" : "Mixcolumn")
  analysisStr = (isa(params.analysis, DPA) ? "DPA" : "LRA")

  @printf("AES %s %s attack parameters\n", attackStr, analysisStr)
  printParameters(params.analysis)
  @printf("mode:       %s\n", string(params.mode))
  @printf("key length: %s\n", string(params.keyLength))
  @printf("direction:  %s\n", string(params.direction))
  @printf("target:     %s\n", string(targetFunction))
  @printf("data at:    %s\n", string(params.dataOffset))
  @printf("key bytes:  %s\n", string(params.keyByteOffsets))
  if !isnull(params.knownKey)
    @printf("known key:  %s\n", bytes2hex(get(params.knownKey)))
  end
end


# get the round key material the attack is recovering to add known key information in the scoring
function getCorrectRoundKeyMaterial(params::AesAttack, phase::Phase)
  if isnull(params.knownKey)
    return Nullable{Vector{UInt8}}()
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

  if phase == PHASE2
    if (mode == CIPHER && direction == BACKWARD) || (mode == INVCIPHER && direction == FORWARD) || (mode == EQINVCIPHER && direction == FORWARD)
      for i in 1:div(rklength,4)
        roundkey[(i-1)*4+1:i*4] = Aes.InvMixColumn(roundkey[(i-1)*4+1:i*4])
      end
    end
  end

  return Nullable{Vector{UInt8}}(roundkey)
end

# filter function for mixcolumns attack so that we don't accept data that's not semi-constant
function filterConstantInput(offsets, data::Vector{UInt8}, constant::UInt8=nothing)
  for i in 1:length(data)
    if !(i in offsets)
      if constant == nothing
        constant = data[i]
      elseif data[i] != constant
        # return nothing (and thus reject the trace)
        return
      end
    end
  end
  return [data[x] for x in offsets]
end


# the mixcolumns attack
function scatask(trs::Trace, params::AesMCAttack, firstTrace=1, numberOfTraces=length(trs), phase::Phase=PHASE1, phaseInput=Nullable{Vector{UInt8}}())
  params.keyLength == KL128 || throw(ErrorException("AesMCAttack only supported for 128 bits keys"))
  params.direction == FORWARD || throw(ErrorException("AesMCAttack only supported in FORWARD direction"))

  mode = params.mode
  keyLength = params.keyLength
  direction = params.direction
  # dataOffsets = params.dataOffsets
  knownKey = params.knownKey
  targetFunction = getTargetFunction(params)

  local scores

  # select the bytes we need
  addDataPass(trs, (x -> x[params.dataOffset + params.keyByteOffsets - 1]))

  # should make this configurable maybe, but doesn't affect the attack (even if constant doesn't match the one in the traces)
  constant = 0x0

  if keyLength != KL128
    throw(Exception("Only KL128 supported for MC attack"))
  end

  myfn = (data,keyBytePosition,keyVal) -> targetFunction(data, keyBytePosition, keyVal, 1, constant)

  if isnull(phaseInput)
    phaseInput = Nullable(zeros(UInt8, 16))
  end

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
  scores = analysis(params, phase, trs, firstTrace, numberOfTraces, myfn, UInt32, collect(UInt8, 0:255), offsets)

  popDataPass(trs)
  popDataPass(trs)

  if scores == nothing
    @printf("No results .. probably means your input traces are not chosen input\n");
    return nothing
  end

  # get the recovered key material
  roundkey::Vector{UInt8} = getRoundKey(scores)

  # put them in their place
  for o in 1:4
    get(phaseInput)[offsets[o]] = roundkey[o]
  end

  if phase == PHASE4
    produce(FINISHED, recoverKey(get(phaseInput), mode, direction))
  else
    produce(PHASERESULT, phaseInput)
  end

end


function getRoundFunction(phase::Phase, params::AesSboxAttack, phaseInput::Nullable{Vector{UInt8}})
  if phase == PHASE2 && params.keyLength != KL128
      if params.keyLength == KL192
        dataWidth = 8
      else
        dataWidth = 16
      end

    # setup the round function to calculate the output or input of the next target round
    if (params.mode == CIPHER && params.direction == BACKWARD) || (params.mode == INVCIPHER && params.direction == FORWARD) || (params.mode == EQINVCIPHER && params.direction == FORWARD)
        roundfn_ = x -> invRound(reshape(x, (4,4)), reshape(get(phaseInput), (4,4)))[end-dataWidth+1:end]
      else
        roundfn_ = x -> round(reshape(x, (4,4)), reshape(get(phaseInput), (4,4)))[1:dataWidth]
    end
    roundfn = Nullable(roundfn_)
  else
    roundfn = Nullable()
  end

  return roundfn
end

# the sbox attack
function scatask(trs::Trace, params::AesSboxAttack, firstTrace=1, numberOfTraces=length(trs), phase::Phase=PHASE1, phaseInput=Nullable{Vector{UInt8}}())
  mode = params.mode
  keyLength = params.keyLength
  direction = params.direction
  # dataOffsets = params.dataOffsets
  knownKey = params.knownKey
  updateInterval = params.updateInterval
  targetFunction = getTargetFunction(params)


  local key, scores

  # FIXME: implement caching of cond avg traces
  # if isfile("hack.bin")
  #   fd = open("hack.bin", "r")
  #   (data,samples) = deserialize(fd)
  #   close(fd)
  # else
  #   @time (data,samples) = readAllTraces(trs, firstTrace, numberOfTraces)
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
  scores = analysis(params, phase, trs, firstTrace, numberOfTraces, targetFunction, UInt8, collect(UInt8, 0:255), params.keyByteOffsets)

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

  if phase == PHASE1 && keyLength == KL128
    # we're done now

    key = recoverKey(roundkey, mode, direction)
    produce(FINISHED, key)
  elseif phase == PHASE1
    # we need another round

    # FIXME: get rid of this hack
    if keyLength == KL192
      params.keyByteOffsets = collect(1:8)
    else
      params.keyByteOffsets = collect(1:16)
    end

    prevroundkey = Nullable(roundkey)
    produce(PHASERESULT, prevroundkey)

  elseif phase == PHASE2
    # done, just some key fiddling left

    # for these mode & direction combinations we actually recovered a InvMixColumn key, so correct it
    if (mode == CIPHER && direction == BACKWARD) || (mode == INVCIPHER && direction == FORWARD) || (mode == EQINVCIPHER && direction == FORWARD)
      for i in 1:div(length(params.keyByteOffsets),4)
        roundkey[(i-1)*4+1:i*4] = Aes.MixColumn(roundkey[(i-1)*4+1:i*4])
      end
    end

    # put the recovered key material in the correct order and run the key schedules
    if (direction == BACKWARD && mode == CIPHER) || (direction == FORWARD && mode != CIPHER)
        keymaterial = vcat(roundkey, get(phaseInput))
    else
        keymaterial = vcat(get(phaseInput), roundkey)
    end

    key = recoverKey(keymaterial, mode, direction)
    produce(FINISHED, key)
  end
end
