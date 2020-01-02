
abstract type AesCM <: Attack{UInt8} end

export AesCMForward

"""
Implementation of the DPA attack on AES GCM by Josh 
Jaffe descibed in:

https://www.iacr.org/archive/ches2007/47270001/47270001.pdf

(Attack does not implenent the initial counter search yet)
"""
struct AesCMForward <: AesCM
  keyLength::AesKeyLength
end

function numberOfPhases(a::AesCM)
    if a.keyLength == KL128
        return 4
    elseif a.keyLength == KL192 || a.keyLength == KL256
        return 5
    else
        error("wrong parameters")
    end
end

function numberOfTargets(a::AesCM,phase::Int)
    if phase == 1
        return 2
    elseif phase == 2
        return 8
    elseif phase == 3
        return 16
    elseif phase == 4
        return 16
    elseif phase == 5
        if a.keyLength == KL192
            return 8
        elseif a.keyLength == KL256
            return 16
        else
            error("wrong parameters")
        end
    else
        error("wrong parameters")
    end
end

function getTargets(a::AesCMForward, phase::Int, phaseInput::AbstractVector{UInt8})
    return [SboxOut(Aes.sbox) for i in 1:numberOfTargets(a,phase)]        
end

roundfn1(x) = x[15:16]

function roundfn2(x,rk0_1516)
    col1 = MixColumn!([0x00,0x00,0x00,sbox[(x[16] ⊻ rk0_1516[2])+1]])
    col2 = MixColumn!([0x00,0x00,sbox[(x[15] ⊻ rk0_1516[1])+1],0x00])
    return vcat(col1,col2)
end

function roundfn3(x,rk1x_1_8)
    state = reshape(vcat(x[1:8] .⊻ rk1x_1_8,zeros(UInt8,8)),4,4)
    state = Aes.SubBytes!(state)
    state[:,3] .= 0x00
    state[:,4] .= 0x00
    state = Aes.ShiftRows!(state)
    state = Aes.MixColumns!(state)

    return vec(state)
end

function roundfnx(x,rkx)
    state = reshape(x .⊻ rkx,4,4)
    state = Aes.SubBytes!(state)
    state = Aes.ShiftRows!(state)
    state = Aes.MixColumns!(state)

    return vec(state)
end

function getDataPass(a::AesCM, phase::Int, phaseInput::AbstractArray{UInt8,1})
    local roundfn

    if phase == 1
        roundfn = x -> x[15:16]
    elseif phase == 2
        roundfn = x -> roundfn2(x,phaseInput[1:2])
    elseif phase == 3
        roundfn = x -> roundfn3(roundfn2(x,phaseInput[1:2]),phaseInput[3:10])
    elseif phase == 4
        roundfn = x -> roundfnx(roundfn3(roundfn2(x,phaseInput[1:2]),phaseInput[3:10]),phaseInput[11:26])
    elseif phase == 5
        if a.keyLength == KL192
            roundfn = x -> roundfnx(roundfnx(roundfn3(roundfn2(x,phaseInput[1:2]),phaseInput[3:10]),phaseInput[11:26]),phaseInput[27:42])[1:8]
        elseif a.keyLength == KL256
            roundfn = x -> roundfnx(roundfnx(roundfn3(roundfn2(x,phaseInput[1:2]),phaseInput[3:10]),phaseInput[11:26]),phaseInput[27:42])
        else
            error("wrong parameters")
        end
    else
        error("wrong parameters")
    end

    return roundfn
end

function correctKeyMaterial(a::AesCM, knownKey::AbstractVector{UInt8})
    len = 42
    if a.keyLength == KL192
        len += 8
    elseif a.keyLength == KL256
        len += 16
    end

    keymaterial = zeros(UInt8,len)

    keylen = Int(a.keyLength)
    aeskey = knownKey[1:keylen]
    iv = knownKey[keylen+1:keylen+12]

    expkey = Aes.KeyExpansion(aeskey, keylength2Nr(keylen),keylength2Nk(keylen))
    rk0 = reshape(expkey[1:16],4,4)

    keymaterial[1:2] = rk0[15:16]

    rk1 = reshape(expkey[17:32],4,4)
    rk2 = reshape(expkey[33:48],4,4)
    rk3 = reshape(expkey[49:64],4,4)
    rk4 = reshape(expkey[65:80],4,4)


    state = reshape(vcat(iv,zeros(UInt8,4)),4,4)
    state = Aes.AddRoundKey!(state,rk0)
    state = Aes.SubBytes!(state)
    state = Aes.ShiftRows!(state)
    state[4,1] = 0x00
    state[3,2] = 0x00
    state = Aes.MixColumns!(state)
    state = Aes.AddRoundKey!(state,rk1)

    keymaterial[3:10] = state[1:8]

    state = Aes.SubBytes!(state)
    state[:,1] .= 0x00
    state[:,2] .= 0x00
    state = Aes.ShiftRows!(state)
    state = Aes.MixColumns!(state)
    state = Aes.AddRoundKey!(state,rk2)

    keymaterial[11:26] = state
    keymaterial[27:42] = rk3

    if a.keyLength == KL192
        keymaterial[43:50] = rk4[1:8]
    elseif a.keyLength == KL256
        keymaterial[43:58] = rk4
    end


    return keymaterial
end

function recoverKey(a::AesCM, keymaterial::AbstractVector{UInt8})
    kl = Int(a.keyLength)

    return Aes.KeyExpansionBackwards(keymaterial[end-kl+1:end], keylength2Nr(kl), keylength2Nk(kl), 3*4)[1:kl]
end

isKeyCorrect(a::AesCM,knownKey::AbstractArray{UInt8,1},recoveredKey::AbstractArray{UInt8,1}) = knownKey[1:length(recoveredKey)] == recoveredKey

keylength(c::AesCMForward) = Int(c.keyLength) + 12

blocklength(::AesCMForward) = 16
