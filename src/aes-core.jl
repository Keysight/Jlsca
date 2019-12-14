# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse
#
# References
# [AES] AES  FIPS-197, Joan Daemen & Vicent Rijmen
# [IHMW] In how many ways can you write Rijndael, Elad Barkan & Eli Biham

const squares = 0

export gf8_mul,gf8_square,gf2_mul,gf8_sqrt,gf8_exp,gf2_dot,KeyExpansion,KeyExpansionBackwards,Cipher,InvCipher,EqInvCipher,EqInvKeyExpansion,Nb,sbox,invsbox

function myinv(s)
  invs = zeros(UInt8, length(s))
  for i in 1:length(invs)
    invs[s[i]+1] = i-1
  end
  return invs
end

export keylength2Nr

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

export keylength2Nk

function keylength2Nk(keylength)
    if keylength == 16
        return 4
    elseif keylength == 24
        return 6
    elseif keylength == 32
        return 8
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

function gf8_square(data::AbstractArray{UInt8}, squares::Int)
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

    o = BitMatrix(undef, xrows, ycols)

    for ind in 1:length(o)
        i,j = Tuple(CartesianIndices(size(o))[ind])
        o[i,j] = gf2_dot(vec(x[i,:]), vec(y[:,j]))
    end

    return o
end

function gf2_mul(A::BitMatrix, x::UInt8)
    # b = reverse(BitArray([parse(string(x)) for x in Base.bin(x,8,false)]))
    b = reverse(BitArray([x == '1' ? 1 : 0 for x in Base.bin(x,8,false)]))
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

function KeyExpansionBackwards(key::AbstractVector{UInt8}, Nr, Nk, offset=Nb*(Nr+1)-Nk)
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

function KeyExpansion(key::AbstractVector{UInt8}, Nr, Nk)
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

function EqInvKeyExpansion(key::AbstractVector{UInt8}, Nr, Nk)
    w = KeyExpansion(key, Nr, Nk)

    for round in 1:(Nr-1)
        w[round*Nb*wz+1:(round+1)*Nb*wz] = InvMixColumns(reshape(w[round*Nb*wz+1:(round+1)*Nb*wz], (4,Nb)))
    end

    return w
end

export SubBytes!

function SubBytes!(state::AbstractArray)
    size(state) == (4,4) || error("wrong dimensions")

    @inbounds for col in 1:4
        for row in 1:4
            state[row,col] = sbox[state[row,col]+1]
        end
    end

    return state
end

export SubBytes

SubBytes(state) = SubBytes!(copy(state))

export InvSubBytes!

function InvSubBytes!(state::AbstractArray)
    size(state) == (4,4) || error("wrong dimensions")

    @inbounds for col in 1:4
        for row in 1:4
            state[row,col] = invsbox[state[row,col]+1]
        end
    end

    return state
end

export InvSubBytes

InvSubBytes(state) = InvSubBytes!(copy(state))

export AddRoundKey!

function AddRoundKey!(state::AbstractMatrix, k::AbstractMatrix)
    (size(state) == (4,4) && size(k) == (4,4)) || error("wrong dimensions")

    @inbounds for col in 1:4
        for row in 1:4
            state[row,col] = state[row,col] ⊻ k[row,col]
        end
    end

    return state
end

export AddRoundKey

AddRoundKey(state,rk) = AddRoundKey!(copy(state),rk)

function create_mclookup()
    table = zeros(UInt8,256,256)
    nX,nY = size(table)
    for x in 1:nX
        for y in 1:nY
            table[x,y] = gf8_mul(UInt8(x-1),UInt8(y-1))
        end
    end

    table
end

const GF8M = create_mclookup()

export MixColumn!

function MixColumn!(s,col=1)
    length(s) >= 4 || error("wrong dimensions")
    col == 1 || size(s)[2] >= col || error("wrong dimensions")
    @inbounds begin
        s_p1 = GF8M[s[1,col]+1, 0x2+1] ⊻ GF8M[s[2,col]+1, 0x3+1] ⊻ s[3,col] ⊻ s[4,col]
        s_p2 = s[1,col] ⊻ GF8M[s[2,col]+1, 0x2+1] ⊻ GF8M[s[3,col]+1, 0x3+1] ⊻ s[4,col]
        s_p3 = s[1,col] ⊻ s[2,col] ⊻ GF8M[s[3,col]+1, 0x2+1] ⊻ GF8M[s[4,col]+1, 0x3+1]
        s_p4 = GF8M[s[1,col]+1, 0x3+1] ⊻ s[2,col] ⊻ s[3,col] ⊻ GF8M[s[4,col]+1, 0x2+1]
        s[1,col] = s_p1
        s[2,col] = s_p2
        s[3,col] = s_p3
        s[4,col] = s_p4
    end
    return s
end

export MixColumn

MixColumn(s::AbstractVector{UInt8}) = MixColumn!(copy(s))

export InvMixColumn!

function InvMixColumn!(s,col=1)
    length(s) >= 4 || error("wrong dimensions")
    col == 1 || size(s)[2] >= col || error("wrong dimensions")
    @inbounds begin
        s_p1 = GF8M[s[1,col]+1, 0xe+1] ⊻ GF8M[s[2,col]+1, 0xb+1] ⊻ GF8M[s[3,col]+1, 0xd+1] ⊻ GF8M[s[4,col]+1, 0x9+1]
        s_p2 = GF8M[s[1,col]+1, 0x9+1] ⊻ GF8M[s[2,col]+1, 0xe+1] ⊻ GF8M[s[3,col]+1, 0xb+1] ⊻ GF8M[s[4,col]+1, 0xd+1]
        s_p3 = GF8M[s[1,col]+1, 0xd+1] ⊻ GF8M[s[2,col]+1, 0x9+1] ⊻ GF8M[s[3,col]+1, 0xe+1] ⊻ GF8M[s[4,col]+1, 0xb+1]
        s_p4 = GF8M[s[1,col]+1, 0xb+1] ⊻ GF8M[s[2,col]+1, 0xd+1] ⊻ GF8M[s[3,col]+1, 0x9+1] ⊻ GF8M[s[4,col]+1, 0xe+1]
        s[1,col] = s_p1
        s[2,col] = s_p2
        s[3,col] = s_p3
        s[4,col] = s_p4
    end
    return s
end

export InvMixColumn

InvMixColumn(s::AbstractVector{UInt8}) = InvMixColumn!(copy(s))

export MixColumns!

function MixColumns!(state::AbstractMatrix)
    size(state) == (4,4) || error("wrong dimensions")
    MixColumn!(state,1)
    MixColumn!(state,2)
    MixColumn!(state,3)
    MixColumn!(state,4)
end

export MixColumns

MixColumns(state) = MixColumns!(copy(state))

export InvMixColumns!

function InvMixColumns!(state::AbstractMatrix)
    size(state) == (4,4) || error("wrong dimensions")
    InvMixColumn!(state,1)
    InvMixColumn!(state,2)
    InvMixColumn!(state,3)
    InvMixColumn!(state,4)
end

export InvMixColumns

InvMixColumns(state) = InvMixColumns!(copy(state))

export  ShiftRows!

function ShiftRows!(state::AbstractMatrix)
    size(state) == (4,4) || error("wrong dimensions")
    @inbounds state[2,1],state[2,2],state[2,3],state[2,4] = state[2,2],state[2,3],state[2,4],state[2,1]
    @inbounds state[3,1],state[3,2],state[3,3],state[3,4] = state[3,3],state[3,4],state[3,1],state[3,2]
    @inbounds state[4,1],state[4,2],state[4,3],state[4,4] = state[4,4],state[4,1],state[4,2],state[4,3]

    return state
end

export ShiftRows

ShiftRows(state) = ShiftRows!(copy(state))

export InvShiftRows!

function InvShiftRows!(state::AbstractMatrix)
    size(state) == (4,4) || error("wrong dimensions")
    @inbounds state[2,1],state[2,2],state[2,3],state[2,4] = state[2,4],state[2,1],state[2,2],state[2,3]
    @inbounds state[3,1],state[3,2],state[3,3],state[3,4] = state[3,3],state[3,4],state[3,1],state[3,2]
    @inbounds state[4,1],state[4,2],state[4,3],state[4,4] = state[4,2],state[4,3],state[4,4],state[4,1]

    return state
end

export InvShiftRows

InvShiftRows(state) = InvShiftRows!(copy(state))

function Cipher(i::AbstractVector{UInt8}, w::AbstractVector{UInt8}, leak::Function=(x,y)->y)
    im = reshape(i, (4,Nb))
    ret = Cipher(im, w, leak)
    return vec(ret)
end

function Cipher(i::AbstractMatrix{UInt8}, w::AbstractVector{UInt8}, leak::Function=(x,y)->y)
    Nr = div(div(length(w),wz),Nb) - 1

    state = copy(i)

    state = leak("r0.input",state)

    roundkey = reshape(w[1:Nb*wz], (4,Nb))
    leak("r0.k_sch", roundkey)

    state = AddRoundKey!(state, roundkey)

    for round in 1:(Nr-1)
        state = leak(@sprintf("r%d.start", round), state)

        state = SubBytes!(state)
        state = leak(@sprintf("r%d.s_box", round), state)

        state = ShiftRows!(state)
        state = leak(@sprintf("r%d.s_row", round), state)

        state = MixColumns!(state)
        state = leak(@sprintf("r%d.m_col", round), state)

        roundkey = reshape(w[round*Nb*wz+1:(round+1)*Nb*wz], (4,Nb))
        leak(@sprintf("r%d.k_sch", round), roundkey)

        state = AddRoundKey!(state, roundkey)
    end

    state = leak(@sprintf("r%d.start", Nr), state)

    prevstate = state
    state = SubBytes!(state)
    state = leak(@sprintf("r%d.s_box", Nr), state)
    # leak(@sprintf("r%d.s_boxXORin", Nr), state .⊻ prevstate)

    state = ShiftRows!(state)
    state = leak(@sprintf("r%d.s_row", Nr), state)

    roundkey = reshape(w[Nr*Nb*wz+1:(Nr+1)*Nb*wz], (4,Nb))
    leak(@sprintf("r%d.k_sch", Nr), roundkey)

    state = AddRoundKey!(state, roundkey)
    leak(@sprintf("r%d.output", Nr), state)

    return state
end

function InvCipher(i::AbstractVector{UInt8}, w::AbstractVector{UInt8}, leak::Function=(x,y)->y)
    im = reshape(i, (4,Nb))
    ret = InvCipher(im, w, leak)
    return vec(ret)
end

function InvCipher(i::AbstractMatrix{UInt8}, w::AbstractVector{UInt8}, leak::Function=(x,y)->y)
    Nr = div(div(length(w),wz),Nb) - 1

    state = copy(i)
    state = leak("r0.iinput", state)

    roundkey = reshape(w[Nr*Nb*wz+1:(Nr+1)*Nb*wz], (4,4))
    leak("r0.ik_sch", roundkey)
    state = AddRoundKey!(state, roundkey)

    for round in (Nr-1):-1:1
        state = leak(@sprintf("r%d.istart", (Nr - round)), state)

        state = InvShiftRows!(state)
        state = leak(@sprintf("r%d.is_row", (Nr - round)), state)

        prevstate = state
        state = InvSubBytes!(state)
        state = leak(@sprintf("r%d.is_box", (Nr - round)), state)
        leak(@sprintf("r%d.is_boxXORin", (Nr - round)), state .⊻ prevstate)

        roundkey = reshape(w[round*Nb*wz+1:(round+1)*Nb*wz], (4,Nb))
        leak(@sprintf("r%d.ik_sch", (Nr - round)), roundkey)

        state = AddRoundKey!(state, roundkey)
        leak(@sprintf("r%d.ik_add", (Nr - round)), state)

        prevstate = state
        state = InvMixColumns!(state)
        leak(@sprintf("r%d.im_colXORin", (Nr - round)), state .⊻ prevstate)
    end

    state = leak(@sprintf("r%d.istart", Nr), state)

    state = InvShiftRows!(state)
    state = leak(@sprintf("r%d.is_row", Nr), state)

    prevstate = state
    state = InvSubBytes!(state)
    state = leak(@sprintf("r%d.is_box", Nr), state)
    leak(@sprintf("r%d.is_boxXORin", Nr), state .⊻ prevstate)

    roundkey = reshape(w[1:Nb*wz], (4,Nb))
    leak(@sprintf("r%d.ik_sch", Nr), roundkey)

    state = AddRoundKey!(state, roundkey)
    state = leak(@sprintf("r%d.ioutput", Nr), state)

    return state
end

function EqInvCipher(i::AbstractVector{UInt8}, w::AbstractVector{UInt8}, leak::Function=(x,y)->y)
    im = reshape(i, (4,Nb))
    ret = EqInvCipher(im, w, leak)
    return vec(ret)
end

function EqInvCipher(i::AbstractMatrix{UInt8}, w::AbstractVector{UInt8}, leak::Function=(x,y)->y)
    Nr = div(div(length(w),wz),Nb) - 1

    state = copy(i)
    state = leak("r0.iinput", state)

    roundkey = reshape(w[Nr*Nb*wz+1:(Nr+1)*Nb*wz], (4,4))
    leak("r0.ik_sch", roundkey)
    state = AddRoundKey!(state, roundkey)

    for round in (Nr-1):-1:1
        state = leak(@sprintf("r%d.istart", (Nr - round)), state)

        prevstate = state
        state = InvSubBytes!(state)
        state = leak(@sprintf("r%d.is_box", (Nr - round)), state)
        leak(@sprintf("r%d.is_boxXORin", (Nr - round)), state .⊻ prevstate)

        state = InvShiftRows!(state)
        state = leak(@sprintf("r%d.is_row", (Nr - round)), state)

        prevstate = state
        state = InvMixColumns!(state)
        state = leak(@sprintf("r%d.im_col", (Nr - round)), state)
        leak(@sprintf("r%d.im_colXORin", (Nr - round)), state .⊻ prevstate)

        roundkey = reshape(w[round*Nb*wz+1:(round+1)*Nb*wz], (4,Nb))
        leak(@sprintf("r%d.ik_sch", (Nr - round)), roundkey)

        state = AddRoundKey!(state, roundkey)
    end

    state = leak(@sprintf("r%d.istart", Nr), state)

    prevstate = state
    state = InvSubBytes!(state)
    state = leak(@sprintf("r%d.is_box", Nr), state)
    leak(@sprintf("r%d.is_boxXORin", Nr), state .⊻ prevstate)

    state = InvShiftRows!(state)
    state = leak(@sprintf("r%d.is_row", Nr), state)

    roundkey = reshape(w[1:Nb*wz], (4,Nb))
    leak(@sprintf("r%d.ik_sch", Nr), roundkey)

    state = AddRoundKey!(state, roundkey)
    state = leak(@sprintf("r%d.ioutput", Nr), state)

    return state
end
