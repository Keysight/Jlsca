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

keyByteValues(a::AesAttack) = collect(UInt8,0:255)

# two types of attacks: sbox or mixcolumn
type AesSboxAttack <: AesAttack
  mode::AesMode
  keyLength::AesKeyLength
  direction::Direction
  xor::Bool
  sbox::Vector{UInt8}
  invsbox::Vector{UInt8}

  function AesSboxAttack()
    return new(CIPHER, KL128, FORWARD, false, Aes.sbox, Aes.invsbox)
  end
end

type AesMCAttack <: AesAttack
  mode::AesMode
  keyLength::AesKeyLength
  direction::Direction
  xor::Bool
  sbox::Vector{UInt8}
  invsbox::Vector{UInt8}

  function AesMCAttack()
    return new(CIPHER, KL128, FORWARD, false, Aes.sbox, Aes.invsbox)
  end
end

# get the round key material the attack is recovering to add known key information in the scoring
function getCorrectRoundKeyMaterial(params::AesAttack, knownKey::Vector{UInt8}, phase::Int)
  mode = params.mode
  direction = params.direction
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
    return roundkey[[o for o in phase:4:16]]
  else
    return roundkey
  end
end

function getNumberOfTargets(params::AesSboxAttack, phase::Int)
  if params.keyLength == KL192 && phase == PHASE2
    return 8
  else
    return 16
  end
end

function getNumberOfTargets(params::AesMCAttack, phase::Int)
  return 4
end

function getPhases(params::AesSboxAttack)
  if params.keyLength == KL128
    return [PHASE1]
  else
    return [PHASE1, PHASE2]
  end
end

function getPhases(params::AesMCAttack)
  return [PHASE1, PHASE2, PHASE3, PHASE4]
end

# target functions
type InvMcOut <: Target{UInt8,UInt32}
  invsbox::Vector{UInt8}
  constant::UInt8
  position::Int
end

function target(a::InvMcOut, x::UInt8, keyByte::UInt8)
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

function target(a::McOut, x::UInt8, keyByte::UInt8)
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

function target(a::McOutXORIn, x::UInt8, keyByte::UInt8)
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

target(a::SboxOut, data::UInt8, keyByte::UInt8) = a.sbox[(data ⊻ keyByte) + 1]
show(io::IO, a::SboxOut) = print(io, "Sbox out")

type InvSboxOut <: Target{UInt8,UInt8}
  invsbox::Vector{UInt8}
end

target(a::InvSboxOut, data::UInt8, keyByte::UInt8) = a.invsbox[(data ⊻ keyByte) + 1]
show(io::IO, a::InvSboxOut) = print(io, "Inverse sbox out")

type SboxOutXORIn <: Target{UInt8,UInt8}
  sbox::Vector{UInt8}
end

target(a::SboxOutXORIn, data::UInt8, keyByte::UInt8) = data ⊻ keyByte ⊻ a.sbox[(data ⊻ keyByte) + 1]
show(io::IO, a::SboxOutXORIn) = print(io, "Sbox out, xor'ed w/ input")

type InvSboxOutXORIn <: Target{UInt8,UInt8}
  sbox::Vector{UInt8}
end

target(a::InvSboxOutXORIn, data::UInt8, keyByte::UInt8) =  data ⊻ keyByte ⊻ a.invsbox[(data ⊻ keyByte) + 1]
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
function recoverKeyHelper(keymaterial::Vector{UInt8}, mode, direction)
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
    key = recoverKeyHelper(phaseInput, mode, direction)
  else
    secondrklen = getNumberOfTargets(params, 2)
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

    key = recoverKeyHelper(keymaterial, mode, direction)
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
  return recoverKeyHelper(reordered, mode, direction)
end

function getTarget(params::AesMCAttack, phase::Int, targetOffset::Int)
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


function getTarget(params::AesSboxAttack, phase::Int, targetOffset::Int)
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
  attackStr = (isa(params, AesSboxAttack) ? "Sbox" : "Mixcolumn")

  @printf("AES %s attack parameters\n", attackStr)
  @printf("mode:       %s\n", string(params.mode))
  @printf("key length: %s\n", string(params.keyLength))
  @printf("direction:  %s\n", string(params.direction))
end


# filter function for mixcolumns attack so that we don't accept data that's not semi-constant
function filterConstantInput(offsets, data::Vector{UInt8}, constant::UInt8)
  for i in 1:16
    if !(i in offsets)
      if data[i] != constant
        # return nothing (and thus reject the trace)
        return Vector{UInt8}(0)
      end
    end
  end
  return [data[x] for x in offsets]
end

function getRoundFunction(params::AesSboxAttack, phase::Int, phaseInput::Vector{UInt8})
  if phase == PHASE2 && params.keyLength != KL128
      if params.keyLength == KL192
        dataWidth = 8
      else
        dataWidth = 16
      end

    # setup the round function to calculate the output or input of the next target round
    if (params.mode == CIPHER && params.direction == BACKWARD) || (params.mode == INVCIPHER && params.direction == FORWARD) || (params.mode == EQINVCIPHER && params.direction == FORWARD)
        roundfn_ = x -> invRound(reshape(x[1:16], (4,4)), reshape(phaseInput, (4,4)))[end-dataWidth+1:end]
      else
        roundfn_ = x -> round(reshape(x[1:16], (4,4)), reshape(phaseInput, (4,4)))[1:dataWidth]
    end
    roundfn = Nullable(roundfn_)
  else
    roundfn = Nullable()
  end

  return roundfn
end

function getRoundFunction(params::AesMCAttack, phase::Int, phaseInput::Vector{UInt8})
  params.keyLength == KL128 || throw(ErrorException("AesMCAttack only supported for 128 bits keys"))
  params.direction == FORWARD || throw(ErrorException("AesMCAttack only supported in FORWARD direction"))
  

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

  # should make this configurable maybe, but doesn't affect the attack (even if constant doesn't match the one in the traces)
  constant = 0x0

  # select only the traces we want
  return Nullable(x -> filterConstantInput(offsets, x, constant))
end
