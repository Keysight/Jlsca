# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using ..Aes
using ..Trs

import Base.show

export AesSboxAttack,AesSboxRoundAttack,AesMCRoundAttack,AesMCAttack,AesKeyLength,AesMode

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

abstract type AbstractAesMCAttack <: AesAttack end

mutable struct AesMCAttack <: AbstractAesMCAttack
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

mutable struct AesMCRoundAttack <: AbstractAesMCAttack
  mode::AesMode
  keyLength::AesKeyLength
  direction::Direction
  sbox::Vector{UInt8}
  invsbox::Vector{UInt8}

  function AesMCRoundAttack()
    return new(CIPHER, KL128, FORWARD, Aes.sbox, Aes.invsbox)
  end
end

keylength(a::AesSboxAttack) = Int(a.keyLength)
keylength(a::AbstractAesMCAttack) = Int(a.keyLength)
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
  elseif isa(params, AbstractAesMCAttack)
    if mode == CIPHER
      return roundkey1 |> x -> reshape(x,4,4) |> ShiftRows |> vec
    else
      return roundkey1 |> x -> reshape(x,4,4) |> InvShiftRows |> vec
    end
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

function numberOfPhases(params::AbstractAesMCAttack)
  return 16
end

# target functions
mutable struct InvMcOut <: Target{UInt8,UInt32,UInt8}
  invsbox::Vector{UInt8}
  constant::UInt8
  position::Int
end

function target(a::InvMcOut, x::UInt8, keyByte::UInt8)
    mcIn = fill(a.constant, (4,1))
    mcIn[a.position] = a.invsbox[(x ⊻ keyByte) + 1]
    mcOut = Aes.InvMixColumn!(mcIn)
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
    mcIn = fill(a.constant, (4,1))
    mcIn[a.position] = a.sbox[(x ⊻ keyByte) + 1]
    mcOut = Aes.MixColumn!(mcIn)
    ret = mcOut[1] |> UInt32
    ret <<= 8
    ret |= mcOut[2]
    ret <<= 8
    ret |= mcOut[3]
    ret <<= 8
    ret |= mcOut[4]

    return ret
end

show(io::IO, a::McOut) = print(io, "MC out")

mutable struct McRoundOut <: Target{UInt64,UInt32,UInt8}
  sbox::Vector{UInt8}
  constant::UInt8
  rowidx::Int
end

function target(a::McRoundOut, col::UInt64, keyByte::UInt8)
    targetinput = col & 0xff |> UInt8
    cipherinput = (col >> 8) & 0xffffffff |> UInt32
    mcIn = fill(a.constant, (4,1))
    mcIn[a.rowidx] = a.sbox[(targetinput ⊻ keyByte) + 1]
    mcOut = Aes.MixColumn!(mcIn)
    ret = mcOut[1] |> UInt32
    ret <<= 8
    ret |= mcOut[2]
    ret <<= 8
    ret |= mcOut[3]
    ret <<= 8
    ret |= mcOut[4]
    ret ⊻= cipherinput

    return ret
end

show(io::IO, a::McRoundOut) = print(io, "MC out XOR round input")

mutable struct InvMcRoundOut <: Target{UInt64,UInt32,UInt8}
  invsbox::Vector{UInt8}
  constant::UInt8
  rowidx::Int
end

function target(a::InvMcRoundOut, col::UInt64, keyByte::UInt8)
    targetinput = col & 0xff |> UInt8
    cipherinput = (col >> 8) & 0xffffffff |> UInt32
    mcIn = fill(a.constant, (4,1))
    mcIn[a.rowidx] = a.invsbox[(targetinput ⊻ keyByte) + 1]
    mcOut = Aes.InvMixColumn!(mcIn)
    ret = mcOut[1] |> UInt32
    ret <<= 8
    ret |= mcOut[2]
    ret <<= 8
    ret |= mcOut[3]
    ret <<= 8
    ret |= mcOut[4]
    ret ⊻= cipherinput

    return ret
end

show(io::IO, a::InvMcRoundOut) = print(io, "Inv MC out XOR round input")

mutable struct McOutXORIn <: Target{UInt8,UInt32,UInt8}
  sbox::Vector{UInt8}
  constant::UInt8
  position::Int
end

function target(a::McOutXORIn, x::UInt8, keyByte::UInt8)
    mcIn = fill(a.constant, (4,1))
    mcIn[a.position] = a.sbox[(x ⊻ keyByte) + 1]
    mcOut = Aes.MixColumn!(copy(mcIn)) .⊻ mcIn
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
    mcIn = fill(a.constant, (4,1))
    mcIn[a.position] = a.sbox[(x ⊻ keyByte) + 1]
    mcOut = Aes.InvMixColumn!(copy(mcIn)) .⊻ mcIn
    ret::UInt32 = 0
    for i in 1:4
      ret <<= 8
      ret |= mcOut[i]
    end
    return ret
end

show(io::IO, a::InvMcOutXORIn) = print(io, "Inverse MC out, XOR'ed w/ input")

struct SboxOut <: Target{UInt8,UInt8,UInt8}
  sbox::Vector{UInt8}
end

@inline target(a::SboxOut, data::UInt8, keyByte::UInt8) = @inbounds a.sbox[(data ⊻ keyByte) + 1]
show(io::IO, a::SboxOut) = print(io, "Sbox out")

struct InvSboxOut <: Target{UInt8,UInt8,UInt8}
  invsbox::Vector{UInt8}
end

@inline target(a::InvSboxOut, data::UInt8, keyByte::UInt8) = @inbounds a.invsbox[(data ⊻ keyByte) + 1]
show(io::IO, a::InvSboxOut) = print(io, "Inverse sbox out")

struct SboxOutXORIn <: Target{UInt8,UInt8,UInt8}
  sbox::Vector{UInt8}
end

target(a::SboxOutXORIn, data::UInt8, keyByte::UInt8) = @inbounds data ⊻ keyByte ⊻ a.sbox[(data ⊻ keyByte) + 1]
show(io::IO, a::SboxOutXORIn) = print(io, "Sbox out, xor'ed w/ input")

struct InvSboxOutXORIn <: Target{UInt8,UInt8,UInt8}
  invsbox::Vector{UInt8}
end

target(a::InvSboxOutXORIn, data::UInt8, keyByte::UInt8) = @inbounds data ⊻ keyByte ⊻ a.invsbox[(data ⊻ keyByte) + 1]
show(io::IO, a::InvSboxOutXORIn) = print(io, "Inverse Sbox out, xor'ed w/ input")

struct AesSboxRoundOut <: Target{UInt16,UInt8,UInt8}
  sbox::Vector{UInt8}
end

target(a::AesSboxRoundOut, data::UInt16, keyByte::UInt8) = @inbounds a.sbox[(UInt8(data & 0xff) ⊻ keyByte) + 1] ⊻ UInt8(data >> 8)
show(io::IO, a::AesSboxRoundOut) = print(io, "Sbox out, xor'ed w/ round out")

struct InvAesSboxRoundOut <: Target{UInt16,UInt8,UInt8}
  invsbox::Vector{UInt8}
end

target(a::InvAesSboxRoundOut, data::UInt16, keyByte::UInt8) = @inbounds a.invsbox[(UInt8(data & 0xff) ⊻ keyByte) + 1] ⊻ UInt8(data >> 8)
show(io::IO, a::InvAesSboxRoundOut) = print(io, "Inverse Sbox out, xor'ed w/ round out")

# some round functions
function invRound(output::Matrix, roundkey::Matrix)
    state = Aes.AddRoundKey!(copy(output), roundkey)
    state = Aes.InvShiftRows!(state)
    state = Aes.InvSubBytes!(state)
    state = Aes.InvMixColumns!(state)
    return state
end

function round(output::Matrix, roundkey::Matrix)
    state = Aes.AddRoundKey!(copy(output), roundkey)
    state = Aes.SubBytes!(state)
    state = Aes.ShiftRows!(state)
    state = Aes.MixColumns!(state)
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

function recoverKey(params::AbstractAesMCAttack, phaseInput::AbstractVector{UInt8}) 
  mode = params.mode
  direction = params.direction

  if mode == CIPHER
    return recoverKeyHelper(phaseInput |> x -> reshape(x,4,4) |> InvShiftRows |>vec, mode, direction)
  else
    return recoverKeyHelper(phaseInput |> x -> reshape(x,4,4) |> ShiftRows |>vec, mode, direction)
  end

end

numberOfTargets(params::AbstractAesMCAttack, phase::Int) = 1

function getTargets(params::AesMCAttack, phase::Int, phaseInput::AbstractVector{UInt8})
  targetrow = (phase-1)%4+1
  if (params.direction == FORWARD && params.mode == CIPHER) || (params.direction == BACKWARD && params.mode != CIPHER)
    if params.xor
      targetfn = McOutXORIn(params.sbox, 0x0, targetrow)
    else
      targetfn = McOut(params.sbox, 0x0, targetrow)
    end
  else
    if params.xor
      targetfn = InvMcOutXORIn(params.invsbox, 0x0, targetrow)
    else
      targetfn = InvMcOut(params.invsbox, 0x0, targetrow)
    end
  end

  return [targetfn for i in 1:1]
end

function getTargets(params::AesMCRoundAttack, phase::Int, phaseInput::AbstractVector{UInt8})
  targetrow = (phase-1)%4+1
  if (params.direction == FORWARD && params.mode == CIPHER) || (params.direction == BACKWARD && params.mode != CIPHER)
      targetfn = McRoundOut(params.sbox, 0x0, targetrow)
  else
      targetfn = InvMcRoundOut(params.invsbox, 0x0, targetrow)
  end

  return [targetfn for i in 1:1]
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
      targetfn = AesSboxRoundOut(params.sbox)
  else
      targetfn = InvAesSboxRoundOut(params.invsbox)
  end

  return [targetfn for i in 1:numberOfTargets(params,phase)]
end

show(io::IO, a::AesSboxRoundAttack) = print(io, "AES Sbox Round ",a.mode, " ",a.keyLength, " ", a.direction)
show(io::IO, a::AesSboxAttack) = print(io, "AES Sbox ",a.mode, " ",a.keyLength, " ", a.direction, a.xor ? " Xor" : "")
show(io::IO, a::AesMCAttack) = print(io, "AES MC ",a.mode, " ",a.keyLength, " ", a.direction, a.xor ? " Xor" : "")
show(io::IO, a::AesMCRoundAttack) = print(io, "AES MC XOR round input ",a.mode, " ",a.keyLength, " ", a.direction)

function printParameters(params::Union{AesSboxAttack,AbstractAesMCAttack})
  @printf("mode:         %s\n", string(params.mode))
  @printf("key length:   %s\n", string(params.keyLength))
  @printf("direction:    %s\n", string(params.direction))
  if isdefined(params,:xor)
    @printf("xor:          %s\n", string(params.xor))
  end
end

function msb32_fromarray(x,offset)
  ret = x[offset+1] |> UInt32
  ret <<= 8
  ret |= x[offset+2]
  ret <<= 8
  ret |= x[offset+3]
  ret <<= 8
  ret |= x[offset+4]
  return ret
end


# filter function for mixcolumns attack so that we don't accept data that's not semi-constant
function filterConstantInputXOR(row::Int, col::Int, data::AbstractVector{UInt8}, constant::UInt8, inv::Bool)
  if inv
    srdata = ShiftRows!(data |> copy |> x -> reshape(x,4,4))
  else
    srdata = InvShiftRows!(data |> copy |> x -> reshape(x,4,4))
  end

  for r in 1:4
    if r != row && srdata[r,col] != constant
      return Vector{UInt64}(undef,0)
    end
  end

  ret = zeros(UInt64,1)

  ret[1] = msb32_fromarray(data,(col-1)*4)
  ret[1] <<= 8
  ret[1] |= srdata[row,col]

  return ret
end

# filter function for mixcolumns attack so that we don't accept data that's not semi-constant
function filterConstantInput(row::Int, col::Int, data::AbstractVector{UInt8}, constant::UInt8, inv::Bool)
  if inv
    srdata = Aes.ShiftRows!(data[1:16] |> x -> reshape(x,4,4))
  else
    srdata = Aes.InvShiftRows!(data[1:16] |> x -> reshape(x,4,4))
  end

  for r in 1:4
    if r != row && srdata[r,col] != constant
        return Vector{UInt8}(undef,0)
    end
  end
  ret = zeros(UInt8,1)

  ret[1] = srdata[row,col]

  return ret
end

function mymerge16(lsbs::AbstractArray{UInt8},msbs::AbstractArray{UInt8})
  length(lsbs) == length(msbs) || throw(DomainError("unequal lengths"))
  l = length(lsbs)
  ret = zeros(UInt16, l)

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
        roundfn2 = x -> (y=roundfn(x); mymerge16(y,ShiftRows!(MixColumns!(reshape(copy(y),(4,4))))))
      else
        roundfn2 = x -> (y=roundfn(x); mymerge16(y,ShiftRows!(reshape(copy(y),(4,4)))))
      end
    else
      if secondrnd && stripMC
        roundfn2 = x -> (y=roundfn(x); mymerge16(y,InvShiftRows!(InvMixColumns!(reshape(copy(y),(4,4))))))
      else
        roundfn2 = x -> (y=roundfn(x); mymerge16(y,InvShiftRows!(reshape(copy(y),(4,4)))))
      end
    end
  else
    roundfn2 = roundfn
  end

  roundfn3 = x -> roundfn2(x)[selection]

  return roundfn3
end

function getDataPass(params::AesMCAttack, phase::Int, phaseInput::AbstractVector{UInt8})
  params.keyLength == KL128 || throw(ErrorException("AesMCAttack only supported for 128 bits keys"))
  params.direction == FORWARD || throw(ErrorException("AesMCAttack only supported in FORWARD direction"))
  
  row = (phase-1)%4+1
  col = div(phase-1,4)+1

  # should make this configurable maybe, but doesn't affect the attack (even if constant doesn't match the one in the traces)
  constant = 0x0

  # select only the traces we want
  return x -> filterConstantInput(row,col,x,constant,params.mode == CIPHER)
end

function getDataPass(params::AesMCRoundAttack, phase::Int, phaseInput::AbstractVector{UInt8})
  params.keyLength == KL128 || throw(ErrorException("AesMCAttack only supported for 128 bits keys"))
  params.direction == FORWARD || throw(ErrorException("AesMCAttack only supported in FORWARD direction"))
  
  row = (phase-1)%4+1
  col = div(phase-1,4)+1

  # should make this configurable maybe, but doesn't affect the attack (even if constant doesn't match the one in the traces)
  constant = 0x0

  # select only the traces we want
  return x -> filterConstantInputXOR(row,col,x,constant,params.mode == CIPHER)
end
