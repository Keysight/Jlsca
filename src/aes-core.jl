# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse
#
# References
# [AES] AES  FIPS-197, Joan Daemen & Vicent Rijmen
# [IHMW] In how many ways can you write Rijndael, Elad Barkan & Eli Biham

const squares = 0

export gf8_mul,gf8_square,gf2_mul,gf8_sqrt,gf8_exp,gf2_dot,KeyExpansion,KeyExpansionBackwards,InvMixColumns,InvMixColumn,MixColumns,MixColumn,ShiftRows,InvShiftRows,AddRoundKey,Cipher,InvCipher,EqInvCipher,EqInvKeyExpansion,SubBytes,InvSubBytes,Nb,sbox,invsbox

function myinv(s)
  invs = zeros(UInt8, length(s))
  for i in 1:length(invs)
    invs[s[i]+1] = i-1
  end
  return invs
end

function keylength2Nr(keylength)
    if keylength == 16
        return 10
    elseif keylength == 24
        return 12
    elseif keylength == 32
        return 14
    end
    throw(ErrorException("invalid keylength $keylength"))
end

const Nb = 4
const wz = sizeof(UInt32)

function bytes(words::UInt32...)
    res = zeros(UInt8, length(words)*4)

    for i in 1:length(words)
        w = words[i]
        res[(i-1)*4+1] = w >> 24
        res[(i-1)*4+2] = (w >> 16) & 0xff
        res[(i-1)*4+3] = (w >> 8) & 0xff
        res[(i-1)*4+4] = w & 0xff
    end

    return res
end

word(a::UInt8, b::UInt8, c::UInt8, d::UInt8) = (UInt32(a) << 24) | (UInt32(b) << 16) | (UInt32(c) << 8) | d
xtime(x::UInt8) = x << 1 ⊻ (x >> 7 == 1 ? 0x1b : 0x0)

RotWord(x::UInt32) = (x >> 24) | (x << 8)

const invQ = BitArray([ 1 0 0 1 0 1 0 1;
                        0 1 1 1 0 0 0 0;
                        0 0 0 1 1 1 0 0;
                        0 1 0 1 0 0 1 0;
                        0 1 0 0 0 0 0 1;
                        0 1 0 1 0 0 0 0;
                        0 1 0 1 0 1 0 0;
                        0 1 0 1 0 1 0 1 ])

# same as Aes.gf8_sqrt(x), taken from [IHMW]
function invQmul(x::UInt8)
    return gf2_mul(invQ, x)
end

const Q = BitArray([ 1 0 0 0 1 0 1 0;
                     0 0 0 0 1 0 1 1;
                     0 1 0 0 0 1 0 0;
                     0 0 0 0 1 1 1 1;
                     0 0 1 0 1 0 0 1;
                     0 0 0 0 0 1 1 0;
                     0 0 0 1 0 1 0 0;
                     0 0 0 0 0 0 1 1 ])


# same as Aes.gf8_mul(x,x), taken from [IHMW]
function Qmul(x::UInt8)
    return gf2_mul(Q, x)
end

function gf8_square(data::Array{UInt8}, squares::Int)
    map(x -> gf8_square(x, squares), data)
end

function gf8_square(x::UInt8, squares::Int)
    if squares == 0
        return x
    end

    s = 1
    Qsquares = Q
    while s < squares
        Qsquares = gf2_mul(Q, Qsquares)
        s += 1
    end

    return gf2_mul(Qsquares, x)
end

# x ^ y in GF(2^8)
function gf8_exp(x::UInt8, y::Int)
    ret::UInt8 = 1

    if y > 0
        ret = x
        for i in 2:y
            ret = gf8_mul(ret, x)
        end
    end

    return ret
end

# x * y in GF(2^8)
function gf8_mul(x::UInt8, y::UInt8)
    e::UInt = 1
    ret::UInt8 = 0

    while e <= y
        if (y & e) == e
            ret ⊻= x
        end
        x = xtime(x)
        e <<= 1
    end

    return ret
end

# x ^ -1 in GF(2^8)
function gf8_inv(x::UInt8)
    if x == 0x0
        return 0x0
    end

    for i in collect(UInt8, 0:255)
        if gf8_mul(x,i) == 0x1
            return i
        end
    end
end

# x ^ (1/2) in GF(2^8)
function gf8_sqrt(x::UInt8)
    for i in collect(UInt8, 0:255)
        if gf8_mul(i,i) == x
            return i
        end
    end
end

function gf2_dot(x::BitVector, y::BitVector)
    length(x) == length(y) || throw(DimensionMismatch())

    res::Bool = false

    for i in 1:length(x)
        res ⊻= (x[i] & y[i])
    end

    return res
end


function gf2_mul(x::BitMatrix, y::BitVector)
    gf2_mul(x, reshape(y, (length(y), 1)))
end

function gf2_mul(x::BitMatrix, y::BitMatrix)
    xrows,xcols = size(x)
    yrows,ycols = size(y)

    xcols == yrows || throw(DimensionMismatch(@sprintf("size(x) == %s, size(y) == %s", size(x), size(y))))

    o = BitMatrix(xrows, ycols)

    for ind in 1:length(o)
        i,j = ind2sub(o,ind)
        o[i,j] = gf2_dot(vec(x[i,:]), vec(y[:,j]))
    end

    return o
end

function gf2_mul(A::BitMatrix, x::UInt8)
    # b = reverse(BitArray([parse(string(x)) for x in bin(x,8,false)]))
    b = reverse(BitArray([x == '1' ? 1 : 0 for x in bin(x,8,false)]))
    Ab = gf2_mul(A, b)

    ret::UInt8 = 0
    for bit in reverse(vec(Ab))
        ret <<= 1
        if bit
            ret |= 1
        end
    end

    return ret
end

# gf2_mul with A as defined in AES std eq 5.2
function Amul(x::UInt8)

    A = BitArray([ 1 0 0 0 1 1 1 1;
                   1 1 0 0 0 1 1 1;
                   1 1 1 0 0 0 1 1;
                   1 1 1 1 0 0 0 1;
                   1 1 1 1 1 0 0 0;
                   0 1 1 1 1 1 0 0;
                   0 0 1 1 1 1 1 0;
                   0 0 0 1 1 1 1 1 ])

    s = 0
    Asquares = A
    while s < squares
        Asquares = gf2_mul(gf2_mul(Q, Asquares), invQ)
        s += 1
    end

    return gf2_mul(Asquares, x)

end

function makeSbox()
    sbox = zeros(UInt8, 256)

    for i in collect(UInt8, 0:255)
        sbox[UInt(i)+1] = Amul(gf8_inv(i)) ⊻ gf8_square(0x63, squares)
    end

    return sbox
end

const sbox = makeSbox()
const invsbox = myinv(sbox)

function SubWord(x::UInt32)
    r::UInt32 = 0
    for i in 0:3
        shift = i*8
        b = (x >> shift) & 0xff
        b = sbox[b+1]
        r = r | (UInt32(b) << shift)
    end
    return r
end

# 2 ^ (i-1) in GF(2^8)
function Rcon(i::UInt32)
    x::UInt8 = gf8_exp(gf8_square(0x2, squares), i-1)

    return UInt32(x) << 24
end

function KeyExpansionBackwards(key::Vector{UInt8}, Nr, Nk, offset=Nb*(Nr+1)-Nk)
    w = zeros(UInt32, Nb*(Nr+1))
    temp::UInt32 = 0

    i = 0
    while (i < Nk)
        w[offset+i+1] = word(key[4*i+1], key[4*i+2], key[4*i+3], key[4*i+4])
        i = i+1
    end

    i = offset+Nk-1
    while (i >= Nk)
        temp = w[i-1+1]
        if i % Nk == 0
            temp = SubWord(RotWord(temp)) ⊻ Rcon(UInt32(div(i,Nk)))
        elseif Nk > 6 && i % Nk == 4
            temp = SubWord(temp)
        end

        w[i-Nk+1] = w[i+1] ⊻ temp
        i = i - 1
    end

    return bytes(w...)
end

function KeyExpansion(key::Vector{UInt8}, Nr, Nk)
    w = zeros(UInt32, Nb*(Nr+1))
    temp::UInt32 = 0

    i = 0
    while (i < Nk)
        w[i+1] = word(key[4*i+1], key[4*i+2], key[4*i+3], key[4*i+4])
        i = i+1
    end

    i = Nk
    while (i < Nb * (Nr+1))
        temp = w[i-1+1]
        if i % Nk == 0
            temp = SubWord(RotWord(temp)) ⊻ Rcon(UInt32(div(i,Nk)))
        elseif Nk > 6 && i % Nk == 4
            temp = SubWord(temp)
        end

        w[i+1] = w[i-Nk+1] ⊻ temp
        i = i + 1
    end

    return bytes(w...)
end

function EqInvKeyExpansion(key::Vector{UInt8}, Nr, Nk)
    w = KeyExpansion(key, Nr, Nk)

    for round in 1:(Nr-1)
        w[round*Nb*wz+1:(round+1)*Nb*wz] = InvMixColumns(reshape(w[round*Nb*wz+1:(round+1)*Nb*wz], (4,Nb)))
    end

    return w
end

function SubBytes(state::Array)
    return map(x -> sbox[x+1], state)
end

function InvSubBytes(state::Array)
    return map(x -> invsbox[x+1], state)
end

function AddRoundKey(state::Matrix, k::Matrix)
    return state .⊻ k
end

function MixColumn(s::Vector{UInt8})
    s_p = zeros(UInt8, 4)
    s_p[1] = gf8_mul(s[1], gf8_square(0x2, squares)) ⊻ gf8_mul(s[2], gf8_square(0x3, squares)) ⊻ s[3] ⊻ s[4]
    s_p[2] = s[1] ⊻ gf8_mul(s[2], gf8_square(0x2, squares)) ⊻ gf8_mul(s[3], gf8_square(0x3, squares)) ⊻ s[4]
    s_p[3] = s[1] ⊻ s[2] ⊻ gf8_mul(s[3], gf8_square(0x2, squares)) ⊻ gf8_mul(s[4], gf8_square(0x3, squares))
    s_p[4] = gf8_mul(s[1], gf8_square(0x3, squares)) ⊻ s[2] ⊻ s[3] ⊻ gf8_mul(s[4], gf8_square(0x2, squares))
    return s_p
end

function InvMixColumn(s::Vector{UInt8})
    s_p = zeros(UInt8, 4)
    s_p[1] = gf8_mul(s[1], gf8_square(0xe, squares)) ⊻ gf8_mul(s[2], gf8_square(0xb, squares)) ⊻ gf8_mul(s[3], gf8_square(0xd, squares)) ⊻ gf8_mul(s[4], gf8_square(0x9, squares))
    s_p[2] = gf8_mul(s[1], gf8_square(0x9, squares)) ⊻ gf8_mul(s[2], gf8_square(0xe, squares)) ⊻ gf8_mul(s[3], gf8_square(0xb, squares)) ⊻ gf8_mul(s[4], gf8_square(0xd, squares))
    s_p[3] = gf8_mul(s[1], gf8_square(0xd, squares)) ⊻ gf8_mul(s[2], gf8_square(0x9, squares)) ⊻ gf8_mul(s[3], gf8_square(0xe, squares)) ⊻ gf8_mul(s[4], gf8_square(0xb, squares))
    s_p[4] = gf8_mul(s[1], gf8_square(0xb, squares)) ⊻ gf8_mul(s[2], gf8_square(0xd, squares)) ⊻ gf8_mul(s[3], gf8_square(0x9, squares)) ⊻ gf8_mul(s[4], gf8_square(0xe, squares))
    return s_p
end

function MixColumns(state::Matrix)
    return mapslices(MixColumn, state, 1)
end

function InvMixColumns(state::Matrix)
    return mapslices(InvMixColumn, state, 1)
end

function ShiftRows(state::Matrix)
    state_p = similar(state)
    state_p[1,:] = state[1,:]
    state_p[2,1:3] = state[2,2:4]
    state_p[2,4] = state[2,1]
    state_p[3,1:2] = state[3,3:4]
    state_p[3,3:4] = state[3,1:2]
    state_p[4,1] = state[4,4]
    state_p[4,2:4] = state[4,1:3]
    return state_p
end

function InvShiftRows(state::Matrix)
    state_p = similar(state)
    state_p[1,:] = state[1,:]
    state_p[2,2:4] = state[2,1:3]
    state_p[2,1] = state[2,4]
    state_p[3,3:4] = state[3,1:2]
    state_p[3,1:2] = state[3,3:4]
    state_p[4,4] = state[4,1]
    state_p[4,1:3] = state[4,2:4]
    return state_p
end

function Cipher(i::Vector{UInt8}, w::Vector{UInt8}, leak::Function=(x,y)->y)
    im = reshape(i, (4,Nb))
    ret = Cipher(im, w, leak)
    return vec(ret)
end

function Cipher(i::Matrix{UInt8}, w::Vector{UInt8}, leak::Function=(x,y)->y)
    Nr = div(div(length(w),wz),Nb) - 1

    state = i

    state = leak("r0.input",state)

    roundkey = reshape(w[1:Nb*wz], (4,Nb))
    leak("r0.k_sch", roundkey)

    state = AddRoundKey(state, roundkey)

    for round in 1:(Nr-1)
        state = leak(@sprintf("r%d.start", round), state)

        prevstate = state
        state = SubBytes(state)
        state = leak(@sprintf("r%d.s_box", round), state)
        leak(@sprintf("r%d.s_boxXORin", round), state .⊻ prevstate)

        state = ShiftRows(state)
        state = leak(@sprintf("r%d.s_row", round), state)

        prevstate = state
        state = MixColumns(state)
        state = leak(@sprintf("r%d.m_col", round), state)
        leak(@sprintf("r%d.m_colXORin", round), state .⊻ prevstate)

        roundkey = reshape(w[round*Nb*wz+1:(round+1)*Nb*wz], (4,Nb))
        leak(@sprintf("r%d.k_sch", round), roundkey)

        state = AddRoundKey(state, roundkey)
    end

    state = leak(@sprintf("r%d.start", Nr), state)

    prevstate = state
    state = SubBytes(state)
    state = leak(@sprintf("r%d.s_box", Nr), state)
    leak(@sprintf("r%d.s_boxXORin", Nr), state .⊻ prevstate)

    state = ShiftRows(state)
    state = leak(@sprintf("r%d.s_row", Nr), state)

    roundkey = reshape(w[Nr*Nb*wz+1:(Nr+1)*Nb*wz], (4,Nb))
    leak(@sprintf("r%d.k_sch", Nr), roundkey)

    state = AddRoundKey(state, roundkey)
    leak(@sprintf("r%d.output", Nr), state)

    return state
end

function InvCipher(i::Vector{UInt8}, w::Vector{UInt8}, leak::Function=(x,y)->y)
    im = reshape(i, (4,Nb))
    ret = InvCipher(im, w, leak)
    return vec(ret)
end

function InvCipher(i::Matrix{UInt8}, w::Vector{UInt8}, leak::Function=(x,y)->y)
    Nr = div(div(length(w),wz),Nb) - 1

    state = i
    state = leak("r0.iinput", state)

    roundkey = reshape(w[Nr*Nb*wz+1:(Nr+1)*Nb*wz], (4,4))
    leak("r0.ik_sch", roundkey)
    state = AddRoundKey(state, roundkey)

    for round in (Nr-1):-1:1
        state = leak(@sprintf("r%d.istart", (Nr - round)), state)

        state = InvShiftRows(state)
        state = leak(@sprintf("r%d.is_row", (Nr - round)), state)

        prevstate = state
        state = InvSubBytes(state)
        state = leak(@sprintf("r%d.is_box", (Nr - round)), state)
        leak(@sprintf("r%d.is_boxXORin", (Nr - round)), state .⊻ prevstate)

        roundkey = reshape(w[round*Nb*wz+1:(round+1)*Nb*wz], (4,Nb))
        leak(@sprintf("r%d.ik_sch", (Nr - round)), roundkey)

        state = AddRoundKey(state, roundkey)
        leak(@sprintf("r%d.ik_add", (Nr - round)), state)

        prevstate = state
        state = InvMixColumns(state)
        leak(@sprintf("r%d.im_colXORin", (Nr - round)), state .⊻ prevstate)
    end

    state = leak(@sprintf("r%d.istart", Nr), state)

    state = InvShiftRows(state)
    state = leak(@sprintf("r%d.is_row", Nr), state)

    prevstate = state
    state = InvSubBytes(state)
    state = leak(@sprintf("r%d.is_box", Nr), state)
    leak(@sprintf("r%d.is_boxXORin", Nr), state .⊻ prevstate)

    roundkey = reshape(w[1:Nb*wz], (4,Nb))
    leak(@sprintf("r%d.ik_sch", Nr), roundkey)

    state = AddRoundKey(state, roundkey)
    state = leak(@sprintf("r%d.ioutput", Nr), state)

    return state
end

function EqInvCipher(i::Vector{UInt8}, w::Vector{UInt8}, leak::Function=(x,y)->y)
    im = reshape(i, (4,Nb))
    ret = EqInvCipher(im, w, leak)
    return vec(ret)
end

function EqInvCipher(i::Matrix{UInt8}, w::Vector{UInt8}, leak::Function=(x,y)->y)
    Nr = div(div(length(w),wz),Nb) - 1

    state = i
    state = leak("r0.iinput", state)

    roundkey = reshape(w[Nr*Nb*wz+1:(Nr+1)*Nb*wz], (4,4))
    leak("r0.ik_sch", roundkey)
    state = AddRoundKey(state, roundkey)

    for round in (Nr-1):-1:1
        state = leak(@sprintf("r%d.istart", (Nr - round)), state)

        prevstate = state
        state = InvSubBytes(state)
        state = leak(@sprintf("r%d.is_box", (Nr - round)), state)
        leak(@sprintf("r%d.is_boxXORin", (Nr - round)), state .⊻ prevstate)

        state = InvShiftRows(state)
        state = leak(@sprintf("r%d.is_row", (Nr - round)), state)

        prevstate = state
        state = InvMixColumns(state)
        state = leak(@sprintf("r%d.im_col", (Nr - round)), state)
        leak(@sprintf("r%d.im_colXORin", (Nr - round)), state .⊻ prevstate)

        roundkey = reshape(w[round*Nb*wz+1:(round+1)*Nb*wz], (4,Nb))
        leak(@sprintf("r%d.ik_sch", (Nr - round)), roundkey)

        state = AddRoundKey(state, roundkey)
    end

    state = leak(@sprintf("r%d.istart", Nr), state)

    prevstate = state
    state = InvSubBytes(state)
    state = leak(@sprintf("r%d.is_box", Nr), state)
    leak(@sprintf("r%d.is_boxXORin", Nr), state .⊻ prevstate)

    state = InvShiftRows(state)
    state = leak(@sprintf("r%d.is_row", Nr), state)

    roundkey = reshape(w[1:Nb*wz], (4,Nb))
    leak(@sprintf("r%d.ik_sch", Nr), roundkey)

    state = AddRoundKey(state, roundkey)
    state = leak(@sprintf("r%d.ioutput", Nr), state)

    return state
end
