# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

const R = UInt128(0xe1) << 120
function block_mul(X::UInt128, Y::UInt128)
    Z = UInt128(0)
    V = UInt128(Y)

    for i in 0:127
        Z = (((X >> (127 - i)) & 1) == 0) ? Z : xor(Z,V)
        V = (V & 1) == 0 ? (V >> 1) : xor(V >> 1, R)
    end

    return Z
end

function ghash(X::UInt128, Y::UInt128, H::UInt128) 
    return block_mul(xor(X,Y),H)
end

export GcmState

type GcmState 
    abits::Int
    cbits::Int
    J0::UInt128
    H::UInt128
    S::UInt128
    w::Vector{UInt8}
    cipher::Function

    function GcmState(iv::Vector{UInt8}, key::Vector{UInt8})
        w = KeyExpansion(key, 10, 4)
        cipher = Cipher
        Hb = cipher([0x00 for i in 1:16], w)
        H = hton(reinterpret(UInt128, Hb)[1])
        if length(iv) == div(96,8)
            J0 = hton(reinterpret(UInt128, vcat(iv, [0x00,0x00,0x00,0x01]))[1])
        else
            ibits = length(iv) * 8
            ipad = 128 * div(ibits + 127,128) - ibits
            blocks = div(ibits + ipad,128)
            J0 = UInt128(0)
            for b in 1:blocks
                o = (b-1)*16
                if b == blocks && ipad > 0
                    tmp = zeros(UInt8,16)
                    ipadbytes = div(ipad,8)
                    tail = 16 - ipadbytes
                    tmp[1:tail] = iv[end-tail+1:end]
                    X = hton(reinterpret(UInt128, tmp)[1])
                    J0 = ghash(X,J0,H)
                else
                    X = hton(reinterpret(UInt128, iv[o+1:o+16])[1])
                    J0 = ghash(X,J0,H)
                end
            end
            final = UInt128(length(iv)*8)
            J0 = ghash(final,J0,H)
        end
        new(0,0,J0,H,0,w,cipher)
    end
end

export setAuth

function setAuth(a::GcmState, Ab::Vector{UInt8})
    abits = length(Ab) * 8
    a.abits = abits
    apad = 128 * div(abits + 127,128) - abits
    blocks = div(abits + apad,128)

    # print("blocks $blocks, apad $apad\n")
    for b in 1:blocks
        if b == blocks && apad > 0
            tmp = zeros(UInt8,16)
            apadbytes = div(apad,8)
            tail = 16 - apadbytes
            tmp[1:tail] = Ab[end-tail+1:end]
            X = hton(reinterpret(UInt128, tmp)[1])
            a.S = ghash(X, a.S, a.H)
        else
            o = (b-1)*16
            X = hton(reinterpret(UInt128, Ab[o+1:o+16])[1])
            a.S = ghash(X, a.S, a.H)
        end
    end
end

export doCipher

function doCipher(a::GcmState, p::Vector{UInt8})
    cbits = length(p) * 8
    a.cbits = cbits
    cpad = 128 * div(cbits + 127,128) - cbits
    blocks = div(cbits + cpad,128)
    J = a.J0
    res = similar(p)
    # print("blocks $blocks, cpad $cpad\n")
    for b in 1:blocks
        o = (b-1)*16
        if b == blocks && cpad > 0
            tmp = zeros(UInt8,16)
            cpadbytes = div(cpad,8)
            tail = 16 - cpadbytes
            tmp[1:tail] = p[end-tail+1:end]
            J += 1
            c = a.cipher(reinterpret(UInt8, [hton(J)]), a.w)
            c[tail+1:end] = 0
            c .⊻= tmp
            X = hton(reinterpret(UInt128, c)[1])
            a.S = ghash(X, a.S, a.H)
            res[o+1:o+tail] = c[1:tail]
        else
            J += 1
            c = a.cipher(reinterpret(UInt8, [hton(J)]), a.w)
            c .⊻= p[o+1:o+16]
            X = hton(reinterpret(UInt128, c)[1])
            a.S = ghash(X, a.S, a.H)
            res[o+1:o+16] = c
        end
    end

    return res
end

export final 

function final(a::GcmState)
    lenA = UInt64(a.abits)
    lenC = UInt64(a.cbits)
    final = (UInt128(lenA) << 64) | lenC
    a.S = ghash(a.S,final,a.H)

    X1 = a.cipher(reinterpret(UInt8, [hton(a.J0)]), a.w)
    X2 = reinterpret(UInt8, [hton(a.S)])
    T = xor.(X1, X2)

    return T
end
