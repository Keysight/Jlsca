# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using ..Aes
using ..Trs

import Base.show

export AesSboxAttack,AesSboxRoundAttack,AesMCAttack,AesKeyLength,AesMode

@enum AesMode CIPHER=1 INVCIPHER=2 EQINVCIPHER=3
@enum AesKeyLength KL128=16 KL192=24 KL256=32

for s in instances(AesMode); @eval export $(Symbol(s)); end
for s in instances(AesKeyLength); @eval export $(Symbol(s)); end

export AesAttack

abstract type AesAttack <: Attack{UInt8} end

blocklength(::AesAttack) = 16

# two types of attacks: sbox or mixcolumn
"""
Attacks the (inverse) Sbox output or input, optionally XOR'ed with the input (or output)
into the (inverse) Sboxes.
"""
mutable struct AesSboxAttack <: AesAttack
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

"""
Attacks the (inverse) Sbox output or input XOR'ed with the round input (or output). This is different from the `AesSboxAttack` with the `xor` flag because there's a ShiftRows inbetween.
"""
mutable struct AesSboxRoundAttack <: AesAttack
  mode::AesMode
  keyLength::AesKeyLength
  direction::Direction
  sbox::Vector{UInt8}
  invsbox::Vector{UInt8}

  function AesSboxRoundAttack()
    return new(CIPHER, KL128, FORWARD, Aes.sbox, Aes.invsbox)
  end
end

mutable struct AesMCAttack <: AesAttack
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

keylength(a::AesSboxAttack) = Int(a.keyLength)
keylength(a::AesMCAttack) = Int(a.keyLength)
keylength(a::AesSboxRoundAttack) = Int(a.keyLength)

# get the round key material the attack is recovering to add known key information in the scoring
function correctKeyMaterial(params::AesAttack, knownKey::AbstractVector{UInt8})
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

  if (isa(params, AesSboxAttack) || isa(params, AesSboxRoundAttack)) && keyLength > KL128
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

function numberOfPhases(params::AesAttack)
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
mutable struct InvMcOut <: Target{UInt8,UInt32,UInt8}
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

mutable struct McOut <: Target{UInt8,UInt32,UInt8}
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

mutable struct McOutXORIn <: Target{UInt8,UInt32,UInt8}
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

mutable struct InvMcOutXORIn <: Target{UInt8,UInt32,UInt8}
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

mutable struct SboxOut <: Target{UInt8,UInt8,UInt8}
  sbox::Vector{UInt8}
end

target(a::SboxOut, data::UInt8, keyByte::UInt8) = a.sbox[(data ⊻ keyByte) + 1]
show(io::IO, a::SboxOut) = print(io, "Sbox out")

mutable struct InvSboxOut <: Target{UInt8,UInt8,UInt8}
  invsbox::Vector{UInt8}
end

target(a::InvSboxOut, data::UInt8, keyByte::UInt8) = a.invsbox[(data ⊻ keyByte) + 1]
show(io::IO, a::InvSboxOut) = print(io, "Inverse sbox out")

mutable struct SboxOutXORIn <: Target{UInt8,UInt8,UInt8}
  sbox::Vector{UInt8}
end

target(a::SboxOutXORIn, data::UInt8, keyByte::UInt8) = data ⊻ keyByte ⊻ a.sbox[(data ⊻ keyByte) + 1]
show(io::IO, a::SboxOutXORIn) = print(io, "Sbox out, xor'ed w/ input")

mutable struct InvSboxOutXORIn <: Target{UInt8,UInt8,UInt8}
  invsbox::Vector{UInt8}
end

target(a::InvSboxOutXORIn, data::UInt8, keyByte::UInt8) =  data ⊻ keyByte ⊻ a.invsbox[(data ⊻ keyByte) + 1]
show(io::IO, a::InvSboxOutXORIn) = print(io, "Inverse Sbox out, xor'ed w/ input")

mutable struct AesRoundOut <: Target{UInt16,UInt8,UInt8}
  sbox::Vector{UInt8}
end

target(a::AesRoundOut, data::UInt16, keyByte::UInt8) = a.sbox[(UInt8(data & 0xff) ⊻ keyByte) + 1] ⊻ UInt8(data >> 8)
show(io::IO, a::AesRoundOut) = print(io, "Sbox out, xor'ed w/ round out")

mutable struct InvAesRoundOut <: Target{UInt16,UInt8,UInt8}
  invsbox::Vector{UInt8}
end

target(a::InvAesRoundOut, data::UInt16, keyByte::UInt8) = a.invsbox[(UInt8(data & 0xff) ⊻ keyByte) + 1] ⊻ UInt8(data >> 8)
show(io::IO, a::InvAesRoundOut) = print(io, "Inverse Sbox out, xor'ed w/ round out")

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
function recoverKeyHelper(keymaterial::AbstractVector{UInt8}, mode, direction)
  if (mode == CIPHER && direction == FORWARD) || (mode == INVCIPHER && direction == BACKWARD) || (mode == EQINVCIPHER && direction == BACKWARD)
      return keymaterial
    else
      Nk = div(length(keymaterial),Aes.wz)
      Nr = Aes.keylength2Nr(length(keymaterial))
      w = Aes.KeyExpansionBackwards(keymaterial, Nr, Nk)
      return w[1:Nk*Aes.wz]
    end
end

function recoverKey(params::AesAttack, phaseInputOrig::AbstractVector{UInt8})
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

function recoverKey(params::AesMCAttack, phaseInput::AbstractVector{UInt8}) 
  mode = params.mode
  direction = params.direction

  reordered = Vector{UInt8}(undef,16)
  for i in 0:3
    reordered[i*4+1:i*4+4] = phaseInput[[o for o in i+1:4:16]]
  end
  return recoverKeyHelper(reordered, mode, direction)
end

numberOfTargets(params::AesMCAttack, phase::Int) = 4

function getTargets(params::AesMCAttack, phase::Int, phaseInput::AbstractVector{UInt8})
  if (params.direction == FORWARD && params.mode == CIPHER) || (params.direction == BACKWARD && params.mode != CIPHER)
    if params.xor
      targetfn = McOutXORIn(params.sbox, 0x0, phase)
    else
      targetfn = McOut(params.sbox, 0x0, phase)
    end
  else
    if params.xor
      targetfn = InvMcOutXORIn(params.invsbox, 0x0, phase)
    else
      targetfn = InvMcOut(params.invsbox, 0x0, phase)
    end
  end

  return [targetfn for i in 1:4]
end

numberOfTargets(params::AesAttack, phase::Int) = (params.keyLength == KL192 && phase == PHASE2) ? 8 : 16

function getTargets(params::AesSboxAttack, phase::Int, phaseInput::AbstractVector{UInt8})
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

function getTargets(params::AesSboxRoundAttack, phase::Int, phaseInput::AbstractVector{UInt8})
  if (params.direction == FORWARD && params.mode == CIPHER) || (params.direction == BACKWARD && params.mode != CIPHER)
      targetfn = AesRoundOut(params.sbox)
  else
      targetfn = InvAesRoundOut(params.invsbox)
  end

  return [targetfn for i in 1:numberOfTargets(params,phase)]
end

show(io::IO, a::AesSboxRoundAttack) = print(io, "AES Sbox Round ",a.mode, " ",a.keyLength, " ", a.direction)
show(io::IO, a::AesSboxAttack) = print(io, "AES Sbox ",a.mode, " ",a.keyLength, " ", a.direction, a.xor ? " Xor" : "")
show(io::IO, a::AesMCAttack) = print(io, "AES MC ",a.mode, " ",a.keyLength, " ", a.direction, a.xor ? " Xor" : "")

function printParameters(params::Union{AesSboxAttack,AesMCAttack})
  @printf("mode:         %s\n", string(params.mode))
  @printf("key length:   %s\n", string(params.keyLength))
  @printf("direction:    %s\n", string(params.direction))
  @printf("xor:          %s\n", string(params.xor))
end


# filter function for mixcolumns attack so that we don't accept data that's not semi-constant
function filterConstantInput(offsets, data::AbstractVector{UInt8}, constant::UInt8)
  for i in 1:16
    if !(i in offsets)
      if data[i] != constant
        # return nothing (and thus reject the trace)
        return Vector{UInt8}(undef,0)
      end
    end
  end
  return [data[x] for x in offsets]
end

function mymerge16(lsbs::AbstractArray{UInt8},msbs::AbstractArray{UInt8})
  length(lsbs) == length(msbs) || throw(DomainError("unequal lengths"))
  l = length(lsbs)
  ret = zeros(UInt16, l)

  # print("input ", bytes2hex(lsbs),"\n")
  # print("srowed input ", bytes2hex(msbs),"\n")
  for i in 1:l
    ret[i] = (UInt16(msbs[i]) << 8) | lsbs[i]
  end

  return ret
end

function getDataPass(params::AesAttack, phase::Int, phaseInput::AbstractVector{UInt8})
  cond = (params.mode == CIPHER && params.direction == BACKWARD) || (params.mode == INVCIPHER && params.direction == FORWARD) || (params.mode == EQINVCIPHER && params.direction == FORWARD)
  stripMC = (params.mode == CIPHER && params.direction == BACKWARD) || (params.mode == INVCIPHER) || (params.mode == EQINVCIPHER && params.direction == BACKWARD)

  secondrnd = phase == PHASE2 && params.keyLength != KL128
  selection = 1:16
  local roundfn

  if secondrnd
    if params.keyLength == KL192
      dataWidth = 8
    else
      dataWidth = 16
    end

    # setup the round function to calculate the output or input of the next target round
    if cond
        roundfn = x -> invRound(reshape(x[1:16], (4,4)), reshape(phaseInput, (4,4)))
        selection = (16-dataWidth)+1:16
    else
        roundfn = x -> round(reshape(x[1:16], (4,4)), reshape(phaseInput, (4,4)))
        selection = 1:dataWidth
    end
  else
    roundfn = x -> x[1:16]
  end

  if isa(params,AesSboxRoundAttack)
    if cond
      if secondrnd && stripMC
        roundfn2 = x -> (y=roundfn(x); mymerge16(y,ShiftRows(MixColumns(reshape(y,(4,4))))))
      else
        roundfn2 = x -> (y=roundfn(x); mymerge16(y,ShiftRows(reshape(y,(4,4)))))
      end
    else
      if secondrnd && stripMC
        roundfn2 = x -> (y=roundfn(x); mymerge16(y,InvShiftRows(InvMixColumns(reshape(y,(4,4))))))
      else
        roundfn2 = x -> (y=roundfn(x); mymerge16(y,InvShiftRows(reshape(y,(4,4)))))
      end
    end
  else
    roundfn2 = roundfn
  end

  # if selection != 1:16
    roundfn3 = x -> roundfn2(x)[selection]
  # else 
    # roundfn3 = roundfn2
  # end

  return roundfn3
end

function getDataPass(params::AesMCAttack, phase::Int, phaseInput::AbstractVector{UInt8})
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
  return x -> filterConstantInput(offsets, x, constant)
end
