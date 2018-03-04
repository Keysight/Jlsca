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

export AesAttack

abstract type AesAttack <: Attack{UInt8} end

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
function correctKeyMaterial(params::AesAttack, knownKey::Vector{UInt8})
  mode = params.mode
  direction = params.direction
  keyLength = params.keyLength

  Nk = div(length(knownKey),Aes.wz)
  Nr = Aes.keylength2Nr(length(knownKey))
  w = Aes.KeyExpansion(knownKey, Nr, Nk)

  fwkeysched = (mode == CIPHER && direction == FORWARD) || (mode == INVCIPHER && direction == BACKWARD) || (mode == EQINVCIPHER && direction == BACKWARD)

  if fwkeysched
    roundkey1 = w[1:16]
  else
    roundkey1 = w[end-16+1:end]
  end

  if isa(params, AesSboxAttack) && keyLength > KL128
    rklength = (keyLength == KL192 ? 8 : 16)
    if fwkeysched
      roundkey2 = w[16+1:16+rklength]
    else
      roundkey2 = w[end-16-rklength+1:end-16]
    end

    if !fwkeysched
      for i in 1:div(rklength,4)
        roundkey2[(i-1)*4+1:i*4] = Aes.InvMixColumn(roundkey2[(i-1)*4+1:i*4])
      end
    end

    return vcat(roundkey1, roundkey2)
  elseif isa(params, AesMCAttack)
    return roundkey1[reduce(vcat, [[o for o in i:4:16] for i in 1:4])]
  else
    return roundkey1
  end
end

function numberOfPhases(params::AesSboxAttack)
  if params.keyLength == KL128
    return PHASE1
  else
    return PHASE2
  end
end

function numberOfPhases(params::AesMCAttack)
  return PHASE4
end

# target functions
type InvMcOut <: Target{UInt8,UInt32,UInt8}
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

type McOut <: Target{UInt8,UInt32,UInt8}
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

type McOutXORIn <: Target{UInt8,UInt32,UInt8}
  sbox::Vector{UInt8}
  constant::UInt8
  position::Int
end

function target(a::McOutXORIn, x::UInt8, keyByte::UInt8)
    mcIn = fill(a.constant, 4)
    mcIn[a.position] = a.sbox[(x ⊻ keyByte) + 1]
    mcOut = Aes.MixColumn(mcIn) .⊻ mcIn
    ret::UInt32 = 0
    for i in 1:4
      ret <<= 8
      ret |= mcOut[i]
    end
    return ret
end

show(io::IO, a::McOutXORIn) = print(io, "MC out, XOR'ed w/ input")

type InvMcOutXORIn <: Target{UInt8,UInt32,UInt8}
  sbox::Vector{UInt8}
  constant::UInt8
  position::Int
end

function target(a::InvMcOutXORIn, x::UInt8, keyByte::UInt8)
    mcIn = fill(a.constant, 4)
    mcIn[a.position] = a.sbox[(x ⊻ keyByte) + 1]
    mcOut = Aes.InvMixColumn(mcIn) .⊻ mcIn
    ret::UInt32 = 0
    for i in 1:4
      ret <<= 8
      ret |= mcOut[i]
    end
    return ret
end

show(io::IO, a::InvMcOutXORIn) = print(io, "Inverse MC out, XOR'ed w/ input")

type SboxOut <: Target{UInt8,UInt8,UInt8}
  sbox::Vector{UInt8}
end

target(a::SboxOut, data::UInt8, keyByte::UInt8) = a.sbox[(data ⊻ keyByte) + 1]
show(io::IO, a::SboxOut) = print(io, "Sbox out")

type InvSboxOut <: Target{UInt8,UInt8,UInt8}
  invsbox::Vector{UInt8}
end

target(a::InvSboxOut, data::UInt8, keyByte::UInt8) = a.invsbox[(data ⊻ keyByte) + 1]
show(io::IO, a::InvSboxOut) = print(io, "Inverse sbox out")

type SboxOutXORIn <: Target{UInt8,UInt8,UInt8}
  sbox::Vector{UInt8}
end

target(a::SboxOutXORIn, data::UInt8, keyByte::UInt8) = data ⊻ keyByte ⊻ a.sbox[(data ⊻ keyByte) + 1]
show(io::IO, a::SboxOutXORIn) = print(io, "Sbox out, xor'ed w/ input")

type InvSboxOutXORIn <: Target{UInt8,UInt8,UInt8}
  invsbox::Vector{UInt8}
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

function recoverKey(params::AesSboxAttack, phaseInputOrig::Vector{UInt8})
  mode = params.mode
  direction = params.direction
  phaseInput = copy(phaseInputOrig)

  if params.keyLength == KL128
    key = recoverKeyHelper(phaseInput, mode, direction)
  else
    secondrklen = (KL192 == params.keyLength ? 8 : 16)
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

numberOfTargets(params::AesMCAttack, phase::Int) = 4

function getTargets(params::AesMCAttack, phase::Int, phaseInput::Vector{UInt8})
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

  return [targetfn for i in 1:4]
end

numberOfTargets(params::AesSboxAttack, phase::Int) = (params.keyLength == KL192 && phase == PHASE2) ? 8 : 16

function getTargets(params::AesSboxAttack, phase::Int, phaseInput::Vector{UInt8})
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

  return [targetfn for i in 1:numberOfTargets(params,phase)]
end

show(io::IO, a::AesSboxAttack) = print(io, "AES Sbox")
show(io::IO, a::AesMCAttack) = print(io, "AES MC")

function printParameters(params::Union{AesSboxAttack,AesMCAttack})
  @printf("mode:         %s\n", string(params.mode))
  @printf("key length:   %s\n", string(params.keyLength))
  @printf("direction:    %s\n", string(params.direction))
  @printf("xor:          %s\n", string(params.xor))
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

function getDataPass(params::AesSboxAttack, phase::Int, phaseInput::Vector{UInt8})
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
    roundfn = Nullable(x -> x[1:16])
  end

  return roundfn
end

function getDataPass(params::AesMCAttack, phase::Int, phaseInput::Vector{UInt8})
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
