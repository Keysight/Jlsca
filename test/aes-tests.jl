# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test


using Jlsca.Aes

function sq(data::Array{UInt8})
    return gf8_square(data, Aes.squares)
end

function testKeyExpansion128()
    key = hex2bytes(replace("2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c", " ", ""))
    key = sq(key)
    w = KeyExpansion(key, 10, 4)

    @test(w[end-8+1:end] == sq(hex2bytes("e13f0cc8b6630ca6")))
end

function testKeyExpansionBackwards128()
    key = hex2bytes(replace("2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c", " ", ""))
    w = KeyExpansion(key, 10, 4)

    res = KeyExpansionBackwards(w[end-16+1:end], 10, 4)

    @test(res == w)
end


function testKeyExpansion192()
    key = hex2bytes(replace(" 8e 73 b0 f7 da 0e 64 52 c8 10 f3 2b 80 90 79 e5 62 f8 ea d2 52 2c 6b 7b", " ", ""))
    key = sq(key)
    w = KeyExpansion(key, 12, 6)

    @test(w[end-8+1:end] == sq(hex2bytes("8ecc720401002202")))
end

function testKeyExpansionBackwards192()
    key = hex2bytes(replace(" 8e 73 b0 f7 da 0e 64 52 c8 10 f3 2b 80 90 79 e5 62 f8 ea d2 52 2c 6b 7b", " ", ""))
    w = KeyExpansion(key, 12, 6)

    res = KeyExpansionBackwards(w[end-24+1:end], 12, 6)

    @test(res == w)
end


function testKeyExpansion256()
    key = hex2bytes(replace("60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4", " ", ""))
    key = sq(key)
    w = KeyExpansion(key, 14, 8)

    @test(w[end-8+1:end] == sq(hex2bytes("046df344706c631e")))
end

function testKeyExpansionBackwards256()
    key = hex2bytes(replace("60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4", " ", ""))
    w = KeyExpansion(key, 14, 8)

    res = KeyExpansionBackwards(w[end-32+1:end], 14, 8)

    @test(res == w)
end

function testEqInvKeyExpansion128()
    key = hex2bytes(replace(" 000102030405060708090a0b0c0d0e0f", " ", ""))
    key = sq(key)
    w = EqInvKeyExpansion(key, 10, 4)

    blegh = hex2bytes(replace("13aa29be9c8faff6f770f58000f7bf03 13111d7fe3944a17f307a78b4d2b30c5 ", " ", ""))
    blegh = sq(blegh)

    @test(w[end-32+1:end] == blegh)
end

function testEqInvKeyExpansion192()
    key = hex2bytes(replace("000102030405060708090a0b0c0d0e0f1011121314151617", " ", ""))
    key = sq(key)
    w = EqInvKeyExpansion(key, 12, 6)

    blegh = hex2bytes(replace("d6bebd0dc209ea494db073803e021bb9 a4970a331a78dc09c418c271e3a41d5d ", " ", ""))
    blegh = sq(blegh)

    @test(w[end-32+1:end] == blegh)
end

function testEqInvKeyExpansion256()
    key = hex2bytes(replace("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", " ", ""))
    key = sq(key)
    w = EqInvKeyExpansion(key, 14, 8)

    blegh = hex2bytes(replace("34f1d1ffbfceaa2ffce9e25f2558016e 24fc79ccbf0979e9371ac23c6d68de36 ", " ", ""))
    blegh = sq(blegh)

    @test(w[end-32+1:end] == blegh)
end





function testKeyExpansions()
    testKeyExpansion128()
    testKeyExpansion192()
    testKeyExpansion256()
    testKeyExpansionBackwards128()
    testKeyExpansionBackwards192()
    testKeyExpansionBackwards256()
    testEqInvKeyExpansion128()
    testEqInvKeyExpansion192()
    testEqInvKeyExpansion256()

end

function testMixColumns()
    state = hex2bytes(replace("d4 e0 b8 1e bf b4 41 27 5d 52 11 98 30 ae f1 e5", " ", ""))
    state = sq(state)
    state = reshape(state, (4,4))'
    state1 = MixColumns(state)
    state2 = reshape(hex2bytes(replace("04 e0 48 28 66 cb f8 06 81 19 d3 26 e5 9a 7a 4c", " ", "")), (4,4))'
    state2 = sq(state2)
    @test(state1 == state2)

    state3 = InvMixColumns(state1)

    @test(state3 == state)
end

function testShiftRows()
    state = reshape(hex2bytes(replace("d4 e0 b8 1e 27 bf b4 41 11 98 5d 52 ae f1 e5 30", " ", "")), (4,4))'
    state1 = ShiftRows(state)
    state2 = reshape(hex2bytes(replace("d4 e0 b8 1e bf b4 41 27 5d 52 11 98 30 ae f1 e5", " ", "")), (4,4))'
    @test(state1 == state2)

    state3 = InvShiftRows(state1)

    @test(state3 == state)
end

function testAddRoundKey()
    state = reshape(hex2bytes(replace("58 1b db 1b 4d 4b e7 6b ca 5a ca b0 f1 ac a8 e5", " ", "")), (4,4))'
    key = reshape(hex2bytes(replace(" f2 7a 59 73 c2 96 35 59 95 b9 80 f6 f2 43 7a 7f", " ", "")), (4,4))'
    state1 = AddRoundKey(state, key)
    state2 = reshape(hex2bytes(replace("aa 61 82 68 8f dd d2 32 5f e3 4a 46 03 ef d2 9a", " ", "")), (4,4))'


    @test(state1 == state2)

    state3 = AddRoundKey(state1, key)

    @test(state3 == state)
end

function testSubBytes()
    state = reshape(sq(hex2bytes(replace("aa 61 82 68 8f dd d2 32 5f e3 4a 46 03 ef d2 9a", " ", ""))), (4,4))'
    state1 = SubBytes(state)
    state2 = reshape(sq(hex2bytes(replace("ac ef 13 45 73 c1 b5 23 cf 11 d6 5a 7b df b5 b8", " ", ""))), (4,4))'
    @test(state1 == state2)

    state3 = InvSubBytes(state1)

    @test(state3 == state)
end



function testCipher128()
    input = hex2bytes(replace(" 00112233445566778899aabbccddeeff", " ", ""))
    input = sq(input)
    key = hex2bytes(replace(" 000102030405060708090a0b0c0d0e0f", " ", ""))
    key = sq(key)
    jaja = hex2bytes(replace("69c4e0d86a7b0430d8cdb78070b4c55a", " ", ""))
    jaja = sq(jaja)

    output = Cipher(input, KeyExpansion(key, 10, 4))

    @test(output == jaja)

    ogog = InvCipher(output, KeyExpansion(key, 10, 4))

    @test(input == ogog)

    output = EqInvCipher(jaja, EqInvKeyExpansion(key, 10, 4))

    @test(output == input)
end

function testCipher192()
    input = hex2bytes(replace(" 00112233445566778899aabbccddeeff", " ", ""))
    input = sq(input)
    key = hex2bytes(replace("  000102030405060708090a0b0c0d0e0f1011121314151617 ", " ", ""))
    key = sq(key)
    jaja = hex2bytes(replace("dda97ca4864cdfe06eaf70a0ec0d7191 ", " ", ""))
    jaja = sq(jaja)

    output = Cipher(input, KeyExpansion(key, 12, 6))

    @test(output == jaja)

    ogog = InvCipher(output, KeyExpansion(key, 12, 6))

    @test(input == ogog)

    output = EqInvCipher(jaja, EqInvKeyExpansion(key, 12, 6))

    @test(output == input)
end

function testCipher256()
    input = hex2bytes(replace(" 00112233445566778899aabbccddeeff", " ", ""))
    input = sq(input)
    key = hex2bytes(replace("   000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f ", " ", ""))
    key = sq(key)
    jaja = hex2bytes(replace("8ea2b7ca516745bfeafc49904b496089 ", " ", ""))
    jaja = sq(jaja)

    output = Cipher(input, KeyExpansion(key, 14, 8))

    @test(output == jaja)

    ogog = InvCipher(output, KeyExpansion(key, 14, 8))

    @test(input == ogog)

    output = EqInvCipher(jaja, EqInvKeyExpansion(key, 14, 8))

    @test(output == input)
end

function printState(s::Matrix{UInt8})
    for r in 1:4
        for c in 1:Nb
            @printf("%02x ", s[r,c])
        end
        @printf("\n")
    end
    @printf("\n")
end

function printVector(s::Vector{UInt8})
    for r in 1:length(s)
            @printf("%02x ", s[r])
            if r%16 == 0 && r!=length(s)
                @printf("\n")
            end
    end
    @printf("\n")
end

function rewrite(targetstr::String, targetstate::Matrix, str::String, origstate::Matrix)
    if str == targetstr
        @printf("REWRITING state\n")
        origstate = targetstate
    end
    return origstate

end

function verbose(str::String, state::Matrix)
    # @printf("%s:\t", str)
    # printVector(vec(state))
    return state

end

function testCipher128TVLA()
    input = hex2bytes(replace(" 00112233445566778899aabbccddeeff", " ", ""))
    # key = hex2bytes(replace(" 000102030405060708090a0b0c0d0e0f", " ", ""))
    rx_s_box = reshape([UInt8(0) for x in 1:16], (4,Nb))
    rx_s_box[2,2] = 1
    rx_s_box[3,2] = 1
    rx_s_row = ShiftRows(rx_s_box)
    rx_m_col = MixColumns(rx_s_row)
    rx_k_sch = reshape([invsbox[1] for x in 1:16], (4,Nb))
    rx_k_sch .⊻= rx_m_col

    key = KeyExpansionBackwards(vec(rx_k_sch), 10, 4, 5*4)[1:16]

    output = Cipher(input, KeyExpansion(key, 10, 4), (x,y)->rewrite("r5.s_box",rx_s_box,x,y))

    newinput = InvCipher(output, KeyExpansion(key, 10, 4))

    newoutput = Cipher(newinput, KeyExpansion(key, 10, 4), verbose)

    @test(output == newoutput)

end

function testCipher192TVLA()
    input = hex2bytes(replace(" 00112233445566778899aabbccddeeff", " ", ""))
    # key = hex2bytes(replace(" 000102030405060708090a0b0c0d0e0f", " ", ""))
    rx_s_box = reshape([UInt8(0) for x in 1:16], (4,Nb))
    rx_s_box[2,2] = 1
    rx_s_box[3,2] = 1
    rx_s_row = ShiftRows(rx_s_box)
    rx_m_col = MixColumns(rx_s_row)
    rx_k_sch = reshape([invsbox[1] for x in 1:16], (4,Nb))
    rx_k_sch .⊻= rx_m_col
    ry_s_sbox = SubBytes(rx_m_col .⊻ rx_k_sch)
    ry_s_row = ShiftRows(ry_s_sbox)
    ry_m_col = MixColumns(ry_s_row)
    ry_k_sch = reshape([invsbox[1] for x in 1:16], (4,Nb))
    ry_k_sch .⊻= ry_m_col

    key = KeyExpansionBackwards(vcat(vec(rx_k_sch),vec(ry_k_sch)[1:8]), 12, 6, 5*4)[1:32]

    output = Cipher(input, KeyExpansion(key, 12, 6), (x,y)->rewrite("r5.s_box",rx_s_box,x,y))

    newinput = InvCipher(output, KeyExpansion(key, 12, 6))

    newoutput = Cipher(newinput, KeyExpansion(key, 12, 6), verbose)

    @test(output == newoutput)

end

function testCipher256TVLA()
    input = hex2bytes(replace(" 00112233445566778899aabbccddeeff", " ", ""))
    # key = hex2bytes(replace(" 000102030405060708090a0b0c0d0e0f", " ", ""))
    rx_s_box = reshape([UInt8(0) for x in 1:16], (4,Nb))
    rx_s_box[2,2] = 1
    rx_s_box[3,2] = 1
    rx_s_row = ShiftRows(rx_s_box)
    rx_m_col = MixColumns(rx_s_row)
    rx_k_sch = reshape([invsbox[1] for x in 1:16], (4,Nb))
    rx_k_sch .⊻= rx_m_col
    ry_s_sbox = SubBytes(rx_m_col .⊻ rx_k_sch)
    ry_s_row = ShiftRows(ry_s_sbox)
    ry_m_col = MixColumns(ry_s_row)
    ry_k_sch = reshape([invsbox[1] for x in 1:16], (4,Nb))
    ry_k_sch .⊻= ry_m_col

    key = KeyExpansionBackwards(vcat(vec(rx_k_sch),vec(ry_k_sch)), 14, 8, 5*4)[1:32]

    output = Cipher(input, KeyExpansion(key, 14, 8), (x,y)->rewrite("r5.s_box",rx_s_box,x,y))

    newinput = InvCipher(output, KeyExpansion(key, 14, 8))

    newoutput = Cipher(newinput, KeyExpansion(key, 14, 8), verbose)

    @test(output == newoutput)

end

function inspTVLA()
    input = hex2bytes(replace(" 725572d7531da3786021980657eed5f7", " ", ""))
    key = hex2bytes(replace(" 7ef7d41bbbbfbe858a1506067f7c7c7b", " ", ""))

    output = Cipher(input, KeyExpansion(key, 10, 4), verbose)


end

function lol()
    a = [UInt8(rand(0:255)) for i in 1:4]
    b = [UInt8(rand(0:255)) for i in 1:4]

    @test(InvMixColumn(a .⊻ b) == InvMixColumn(a) .⊻ InvMixColumn(b))
end

function lol2()
    # r1 = UInt8(rand(0:255))
    # r2 = UInt8(rand(0:255))
    r3 = rand(1:4)

    # c = MixColumn([r1,r1,r1,r1])
    # d = MixColumn([r2,r2,r2,r2])
    c = [UInt8(rand(0:255)) for i in 1:4]
    d = [UInt8(rand(0:255)) for i in 1:4]
    prevmask = nothing
    for b in 0:255
        c[r3] = UInt8(b)
        d[r3] = UInt8(b)
        mask = MixColumn(c) .⊻ MixColumn(d)
        if prevmask != nothing
            # @printf("mask %s\n", bytes2hex(mask))
            @test mask == prevmask
        else
            prevmask = mask
        end
    end
    # @printf("%s\n", bytes2hex(c))
    # c = MixColumn([0xde,0x1,0x1,0x1])
    # @printf("%s\n", bytes2hex(c))

end

testSubBytes()
testMixColumns()
testShiftRows()
testAddRoundKey()
testKeyExpansions()
testCipher128()
testCipher192()
testCipher256()
testCipher128TVLA()
testCipher192TVLA()
testCipher256TVLA()
# inspTVLA()
lol()
lol2()
