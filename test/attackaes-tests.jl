# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Test

using Jlsca.Sca
using Jlsca.Trs
using Jlsca.Aes

function aesleak(key,input,attack,leakfun,ismc=false)
    leakstate = zeros(UInt8,4,4)
    mode = attack.mode
    keyLength = attack.keyLength
    direction = attack.direction

    if mode == CIPHER
        c = Cipher
        w = KeyExpansion(key, keylength2Nr(Int(keyLength)),keylength2Nk(Int(keyLength)))
    elseif mode == INVCIPHER
        c = InvCipher
        w = KeyExpansion(key, keylength2Nr(Int(keyLength)),keylength2Nk(Int(keyLength)))
    elseif mode == EQINVCIPHER
        c = EqInvCipher
        w = EqInvKeyExpansion(key, keylength2Nr(Int(keyLength)),keylength2Nk(Int(keyLength)))
    end

    output = c(input,w,(x,y)->leakfun(x,y,leakstate))
    data = direction == FORWARD ? input : output

    if !ismc
        return output,leakstate,data
    else
        return output,hton.(reinterpret(UInt32,leakstate)),data
    end
end

function lf(label,state,leakstate,match,selection)
    # print(label,"\t", bytes2hex(state),"\n")
    if label == match
        leakstate .= state
        leakstate[1:length(selection)] = leakstate[selection]
    end

    return state
end

function lfxor(label,state,leakstate,match1,match2,selection)
    # print(label,"\t", bytes2hex(state),"\n")
    if label == match1
        leakstate .⊻= state
    elseif label == match2
        leakstate .⊻= state
        leakstate[1:length(selection)] = leakstate[selection]
        # print("xorred ",bytes2hex(leakstate),"\n")
    end

    return state
end

myrand(a,b,c) = rand(a,b)

function attacktester(attack,leaker,leakfuns,randfun=myrand)
    key = rand(UInt8, keylength(attack))
    phases = numberOfPhases(attack)
    knownkeymaterial = Sca.correctKeyMaterial(attack,key)
    # @show bytes2hex(knownkeymaterial)
    phaseInput = Vector{Sca.unittype(attack)}(undef,0)

    for p in 1:phases
        input = randfun(UInt8, blocklength(attack), p)
        phaseDataOffset = offset(attack,p)
        phaseDataLength = numberOfTargets(attack, p)
        rkey = knownkeymaterial[phaseDataOffset+1:phaseDataOffset+phaseDataLength]

        if p > 1
            phaseInput = knownkeymaterial[1:phaseDataOffset]
        end

        if p > length(leakfuns)
            error("incomplete test!")
        end

        output,routput,data = leaker(key,input,attack,leakfuns[p])
        datapass = getDataPass(attack,p,phaseInput)
        rinput = datapass(data)
        # @show rinput
        # @show rkey
        targets = getTargets(attack,p,phaseInput)
        # print(length(targets),"\n")
        for i in eachindex(targets)
            t = targets[i]
            # print("target in ",string(rinput[i],base=16),"\n")
            # print("target key ",string(rkey[i],base=16),"\n")
            ro = target(t,rinput[i],rkey[i])
            # print("target out ",string(ro,base=16),"\n")
            @test ro == routput[i]
        end   
    end

    @test isKeyCorrect(attack,recoverKey(attack,knownkeymaterial),key)

    print("test $attack\n")
end

function sboxattacktest(mode,keyLength,direction,leakfuns)
    attack = AesSboxAttack()
    attack.mode = mode
    attack.keyLength = keyLength
    attack.direction = direction

    attacktester(attack,aesleak,leakfuns) 
end

function sboxxorattacktest(mode,keyLength,direction,leakfuns)
    attack = AesSboxAttack()
    attack.mode = mode
    attack.keyLength = keyLength
    attack.direction = direction
    attack.xor = true

    attacktester(attack,aesleak,leakfuns) 
end

function roundattacktest(mode,keyLength,direction,leakfuns)
    attack = AesSboxRoundAttack()
    attack.mode = mode
    attack.keyLength = keyLength
    attack.direction = direction

    attacktester(attack,aesleak,leakfuns) 
end

function mcrand(a,b,phase)
    return [(i in [o for o in phase:4:16] ? rand(UInt8) : 0x0) for i in 1:16]
end

function mclfcipher(label,state,leakstate,t)
    # print(label,"\t", bytes2hex(state),"\n")
    if label == "r1.s_row"
        leakstate .= state
        leakstate[[i for i in t:4:16]] .= 0
        leakstate[:] = MixColumns(leakstate)
    elseif label == "r1.m_col"
        leakstate .⊻= state
        leakstate[:] = circshift(leakstate,(0,(t-1)))
        # print("prediction: ",bytes2hex(leakstate),"\n")
        # leakstate[:] = InvShiftRows(leakstate)
    end

    return state
end

function mcattacktest(mode,keyLength,direction,leakfuns)
    attack = AesMCAttack()
    attack.mode = mode
    attack.keyLength = keyLength
    attack.direction = direction

    attacktester(attack,(a,b,c,d)->aesleak(a,b,c,d,true),leakfuns,mcrand) 
end

function mcxorattacktest(mode,keyLength,direction,leakfuns)
    attack = AesMCAttack()
    attack.mode = mode
    attack.keyLength = keyLength
    attack.direction = direction
    attack.xor = true

    attacktester(attack,(a,b,c,d)->aesleak(a,b,c,d,true),leakfuns,mcrand) 
end

# @time testAesTraces(true, BACKWARD, CPA())
# @time testAesTraces(true, FORWARD, CPA())
# @time testAesTraces(false, BACKWARD, CPA())
# @time testAesTraces(false, FORWARD, CPA())
# @time testAesTraces(true, FORWARD, LRA(), true)

# @time testAesTraces(false, BACKWARD, CPA(),false,true)
# @time  testAesTraces(false, FORWARD, CPA(),false,true)

const m = reshape(collect(1:16), (4,4))

roundattacktest(CIPHER,KL128,FORWARD,[(x,y,z)->lfxor(x,y,z,"r0.input","r1.s_row",InvShiftRows(m))])
roundattacktest(CIPHER,KL128,BACKWARD,[(x,y,z)->lfxor(x,y,z, "r10.start","r10.output",ShiftRows(m))])
roundattacktest(INVCIPHER,KL128,FORWARD,[(x,y,z)->lfxor(x,y,z,"r0.iinput","r1.is_box",ShiftRows(m))])
roundattacktest(INVCIPHER,KL128,BACKWARD,[(x,y,z)->lfxor(x,y,z, "r10.istart","r10.ioutput",InvShiftRows(m))])
roundattacktest(EQINVCIPHER,KL128,FORWARD,[(x,y,z)->lfxor(x,y,z,"r0.iinput","r1.is_row",ShiftRows(m))])
roundattacktest(EQINVCIPHER,KL128,BACKWARD,[(x,y,z)->lfxor(x,y,z, "r10.istart","r10.ioutput",InvShiftRows(m))])

roundattacktest(CIPHER,KL192,FORWARD,[(x,y,z)->lfxor(x,y,z,"r0.input","r1.s_row",InvShiftRows(m)),
                                   (x,y,z)->lfxor(x,y,z,"r1.m_col","r2.s_row",InvShiftRows(m))])
roundattacktest(CIPHER,KL192,BACKWARD,[(x,y,z)->lfxor(x,y,z, "r12.start","r12.output",ShiftRows(m)),
                                    (x,y,z)->lfxor(x,y,z, "r11.start","r12.start",ShiftRows(m)[9:16])])
roundattacktest(INVCIPHER,KL192,FORWARD,[(x,y,z)->lfxor(x,y,z,"r0.iinput","r1.is_box",ShiftRows(m)),
                                      (x,y,z)->lfxor(x,y,z,"r1.is_box","r2.is_box",ShiftRows(m)[9:16])])
roundattacktest(INVCIPHER,KL192,BACKWARD,[(x,y,z)->lfxor(x,y,z, "r12.istart","r12.ioutput",InvShiftRows(m)),
                                       (x,y,z)->lfxor(x,y,z, "r11.istart","r12.istart",InvShiftRows(m))])
roundattacktest(EQINVCIPHER,KL192,FORWARD,[(x,y,z)->lfxor(x,y,z,"r0.iinput","r1.is_row",ShiftRows(m)),
                                        (x,y,z)->lfxor(x,y,z,"r1.im_col","r2.is_row",ShiftRows(m)[9:16])])
roundattacktest(EQINVCIPHER,KL192,BACKWARD,[(x,y,z)->lfxor(x,y,z, "r12.istart","r12.ioutput",InvShiftRows(m)),
                                         (x,y,z)->lfxor(x,y,z, "r11.istart","r12.istart",InvShiftRows(m))])


roundattacktest(CIPHER,KL256,FORWARD,[(x,y,z)->lfxor(x,y,z,"r0.input","r1.s_row",InvShiftRows(m)),
                                   (x,y,z)->lfxor(x,y,z,"r1.m_col","r2.s_row",InvShiftRows(m))])
roundattacktest(CIPHER,KL256,BACKWARD,[(x,y,z)->lfxor(x,y,z, "r14.start","r14.output",ShiftRows(m)),
                                    (x,y,z)->lfxor(x,y,z, "r13.start","r14.start",ShiftRows(m))])
roundattacktest(INVCIPHER,KL256,FORWARD,[(x,y,z)->lfxor(x,y,z,"r0.iinput","r1.is_box",ShiftRows(m)),
                                      (x,y,z)->lfxor(x,y,z,"r1.is_box","r2.is_box",ShiftRows(m))])
roundattacktest(INVCIPHER,KL256,BACKWARD,[(x,y,z)->lfxor(x,y,z, "r14.istart","r14.ioutput",InvShiftRows(m)),
                                       (x,y,z)->lfxor(x,y,z, "r13.istart","r14.istart",InvShiftRows(m))])
roundattacktest(EQINVCIPHER,KL256,FORWARD,[(x,y,z)->lfxor(x,y,z,"r0.iinput","r1.is_row",ShiftRows(m)),
                                        (x,y,z)->lfxor(x,y,z,"r1.im_col","r2.is_row",ShiftRows(m))])
roundattacktest(EQINVCIPHER,KL256,BACKWARD,[(x,y,z)->lfxor(x,y,z, "r14.istart","r14.ioutput",InvShiftRows(m)),
                                         (x,y,z)->lfxor(x,y,z, "r13.istart","r14.istart",InvShiftRows(m))])

sboxattacktest(CIPHER,KL128,FORWARD,[(x,y,z)->lf(x,y,z,"r1.s_box",1:16)])
sboxattacktest(CIPHER,KL128,BACKWARD,[(x,y,z)->lf(x,y,z,"r10.start",ShiftRows(m))])
sboxattacktest(INVCIPHER,KL128,FORWARD,[(x,y,z)->lf(x,y,z,"r1.is_box",ShiftRows(m))])
sboxattacktest(INVCIPHER,KL128,BACKWARD,[(x,y,z)->lf(x,y,z, "r10.is_row",1:16)])
sboxattacktest(EQINVCIPHER,KL128,FORWARD,[(x,y,z)->lf(x,y,z,"r1.is_box",1:16)])
sboxattacktest(EQINVCIPHER,KL128,BACKWARD,[(x,y,z)->lf(x,y,z,"r10.istart",InvShiftRows(m))])

sboxattacktest(CIPHER,KL192,FORWARD,[(x,y,z)->lf(x,y,z,"r1.s_box",1:16),(x,y,z)->lf(x,y,z,"r2.s_box",1:16)])
sboxattacktest(CIPHER,KL192,BACKWARD,[(x,y,z)->lf(x,y,z,"r12.start",ShiftRows(m)),(x,y,z)->lf(x,y,z,"r11.start",ShiftRows(m)[9:16])])
sboxattacktest(INVCIPHER,KL192,FORWARD,[(x,y,z)->lf(x,y,z,"r1.is_box",ShiftRows(m)),(x,y,z)->lf(x,y,z,"r2.is_box",ShiftRows(m)[9:16])])
sboxattacktest(INVCIPHER,KL192,BACKWARD,[(x,y,z)->lf(x,y,z, "r12.is_row",1:16),(x,y,z)->lf(x,y,z, "r11.is_row",1:16)])
sboxattacktest(EQINVCIPHER,KL192,FORWARD,[(x,y,z)->lf(x,y,z,"r1.is_box",1:16),(x,y,z)->lf(x,y,z,"r2.is_box",9:16)])
sboxattacktest(EQINVCIPHER,KL192,BACKWARD,[(x,y,z)->lf(x,y,z,"r12.istart",InvShiftRows(m)),(x,y,z)->lf(x,y,z,"r11.istart",InvShiftRows(m))])

sboxattacktest(CIPHER,KL256,FORWARD,[(x,y,z)->lf(x,y,z,"r1.s_box",1:16),(x,y,z)->lf(x,y,z,"r2.s_box",1:16)])
sboxattacktest(CIPHER,KL256,BACKWARD,[(x,y,z)->lf(x,y,z,"r14.start",ShiftRows(m)),(x,y,z)->lf(x,y,z,"r13.start",ShiftRows(m))])
sboxattacktest(INVCIPHER,KL256,FORWARD,[(x,y,z)->lf(x,y,z,"r1.is_box",ShiftRows(m)),(x,y,z)->lf(x,y,z,"r2.is_box",ShiftRows(m))])
sboxattacktest(INVCIPHER,KL256,BACKWARD,[(x,y,z)->lf(x,y,z, "r14.is_row",1:16),(x,y,z)->lf(x,y,z, "r13.is_row",1:16)])
sboxattacktest(EQINVCIPHER,KL256,FORWARD,[(x,y,z)->lf(x,y,z,"r1.is_box",1:16),(x,y,z)->lf(x,y,z,"r2.is_box",1:16)])
sboxattacktest(EQINVCIPHER,KL256,BACKWARD,[(x,y,z)->lf(x,y,z,"r14.istart",InvShiftRows(m)),(x,y,z)->lf(x,y,z,"r13.istart",InvShiftRows(m))])


sboxxorattacktest(CIPHER,KL128,FORWARD,[(x,y,z)->lfxor(x,y,z,"r1.start","r1.s_box",1:16)])
sboxxorattacktest(CIPHER,KL128,BACKWARD,[(x,y,z)->lfxor(x,y,z,"r10.start","r10.s_box",ShiftRows(m))])
sboxxorattacktest(INVCIPHER,KL128,FORWARD,[(x,y,z)->lfxor(x,y,z,"r1.is_row","r1.is_box",ShiftRows(m))])
sboxxorattacktest(INVCIPHER,KL128,BACKWARD,[(x,y,z)->lfxor(x,y,z, "r10.is_row","r10.is_box",1:16)])
sboxxorattacktest(EQINVCIPHER,KL128,FORWARD,[(x,y,z)->lfxor(x,y,z,"r1.istart","r1.is_box",1:16)])
sboxxorattacktest(EQINVCIPHER,KL128,BACKWARD,[(x,y,z)->lfxor(x,y,z,"r10.istart","r10.is_box",InvShiftRows(m))])

sboxxorattacktest(CIPHER,KL192,FORWARD,[(x,y,z)->lfxor(x,y,z,"r1.start","r1.s_box",1:16),(x,y,z)->lfxor(x,y,z,"r2.start","r2.s_box",1:16)])
sboxxorattacktest(CIPHER,KL192,BACKWARD,[(x,y,z)->lfxor(x,y,z,"r12.start","r12.s_box",ShiftRows(m)),(x,y,z)->lfxor(x,y,z,"r11.start","r11.s_box",ShiftRows(m)[9:16])])
sboxxorattacktest(INVCIPHER,KL192,FORWARD,[(x,y,z)->lfxor(x,y,z,"r1.is_row","r1.is_box",ShiftRows(m)),(x,y,z)->lfxor(x,y,z,"r2.is_row","r2.is_box",ShiftRows(m)[9:16])])
sboxxorattacktest(INVCIPHER,KL192,BACKWARD,[(x,y,z)->lfxor(x,y,z,"r12.is_row","r12.is_box",1:16),(x,y,z)->lfxor(x,y,z,"r11.is_row","r11.is_box",1:16)])
sboxxorattacktest(EQINVCIPHER,KL192,FORWARD,[(x,y,z)->lfxor(x,y,z,"r1.istart","r1.is_box",1:16),(x,y,z)->lfxor(x,y,z,"r2.istart","r2.is_box",9:16)])
sboxxorattacktest(EQINVCIPHER,KL192,BACKWARD,[(x,y,z)->lfxor(x,y,z,"r12.istart","r12.is_box",InvShiftRows(m)),(x,y,z)->lfxor(x,y,z,"r11.istart","r11.is_box",InvShiftRows(m))])

sboxxorattacktest(CIPHER,KL256,FORWARD,[(x,y,z)->lfxor(x,y,z,"r1.start","r1.s_box",1:16),(x,y,z)->lfxor(x,y,z,"r2.start","r2.s_box",1:16)])
sboxxorattacktest(CIPHER,KL256,BACKWARD,[(x,y,z)->lfxor(x,y,z,"r14.start","r14.s_box",ShiftRows(m)),(x,y,z)->lfxor(x,y,z,"r13.start","r13.s_box",ShiftRows(m))])
sboxxorattacktest(INVCIPHER,KL256,FORWARD,[(x,y,z)->lfxor(x,y,z,"r1.is_row","r1.is_box",ShiftRows(m)),(x,y,z)->lfxor(x,y,z,"r2.is_row","r2.is_box",ShiftRows(m))])
sboxxorattacktest(INVCIPHER,KL256,BACKWARD,[(x,y,z)->lfxor(x,y,z,"r14.is_row","r14.is_box",1:16),(x,y,z)->lfxor(x,y,z,"r13.is_row","r13.is_box",1:16)])
sboxxorattacktest(EQINVCIPHER,KL256,FORWARD,[(x,y,z)->lfxor(x,y,z,"r1.istart","r1.is_box",1:16),(x,y,z)->lfxor(x,y,z,"r2.istart","r2.is_box",1:16)])
sboxxorattacktest(EQINVCIPHER,KL256,BACKWARD,[(x,y,z)->lfxor(x,y,z,"r14.istart","r14.is_box",InvShiftRows(m)),(x,y,z)->lfxor(x,y,z,"r13.istart","r13.is_box",InvShiftRows(m))])


function mclfcipher(label,state,leakstate,t,x=false)
    # print(label,"\t", bytes2hex(state),"\n")
    if label == "r1.s_row"
        leakstate .= state
        leakstate[[i for i in t:4:16]] .= 0
        leakstate[:] = MixColumns(leakstate)
        if x
            input = similar(state)
            input[:] = state
            input[setdiff(1:4,t),:] .= 0
            leakstate .⊻= input
        end
    elseif label == "r1.m_col"
        leakstate .⊻= state
        leakstate[:] = circshift(leakstate,(0,(t-1)))
        # print("prediction: ",bytes2hex(leakstate),"\n")
        # leakstate[:] = InvShiftRows(leakstate)
    end

    return state
end

mcattacktest(CIPHER,KL128,FORWARD,[(x,y,z)->mclfcipher(x,y,z,1),
                                   (x,y,z)->mclfcipher(x,y,z,2),
                                   (x,y,z)->mclfcipher(x,y,z,3),
                                   (x,y,z)->mclfcipher(x,y,z,4)])

mcxorattacktest(CIPHER,KL128,FORWARD,[(x,y,z)->mclfcipher(x,y,z,1,true),
                                      (x,y,z)->mclfcipher(x,y,z,2,true),
                                      (x,y,z)->mclfcipher(x,y,z,3,true),
                                      (x,y,z)->mclfcipher(x,y,z,4,true)])

function mclfinvcipher(label,state,leakstate,t,x=false)
    # print(label,"\t", bytes2hex(state),"\n")
    if label == "r1.is_box"
        leakstate .= state
        leakstate[[i for i in t:4:16]] .= 0
        leakstate[:] = InvMixColumns(leakstate)
        if x
            input = similar(state)
            input[:] = state
            input[setdiff(1:4,t),:] .= 0
            leakstate .⊻= input
        end
    elseif label == "r1.ik_sch"
        leakstate .⊻= InvMixColumns(state)
    elseif label == "r2.istart"
        leakstate .⊻= state
        leakstate[:] = circshift(leakstate,(0,-(t-1)))
        # print("prediction:\t",bytes2hex(leakstate),"\n")
        # leakstate[:] = InvShiftRows(leakstate)
    end

    return state
end

mcattacktest(INVCIPHER,KL128,FORWARD,[(x,y,z)->mclfinvcipher(x,y,z,1),
                                      (x,y,z)->mclfinvcipher(x,y,z,2),
                                      (x,y,z)->mclfinvcipher(x,y,z,3),
                                      (x,y,z)->mclfinvcipher(x,y,z,4)])

mcxorattacktest(INVCIPHER,KL128,FORWARD,[(x,y,z)->mclfinvcipher(x,y,z,1,true),
                                         (x,y,z)->mclfinvcipher(x,y,z,2,true),
                                         (x,y,z)->mclfinvcipher(x,y,z,3,true),
                                         (x,y,z)->mclfinvcipher(x,y,z,4,true)])


function mclfeqinvcipher(label,state,leakstate,t,x=false)
    # print(label,"\t", bytes2hex(state),"\n")
    if label == "r1.is_row"
        leakstate .= state
        leakstate[[i for i in t:4:16]] .= 0
        leakstate[:] = InvMixColumns(leakstate)
        if x
            input = similar(state)
            input[:] = state
            input[setdiff(1:4,t),:] .= 0
            leakstate .⊻= input
        end
    elseif label == "r1.im_col"
        leakstate .⊻= state
        leakstate[:] = circshift(leakstate,(0,-(t-1)))
        # print("prediction: ",bytes2hex(leakstate),"\n")
        # leakstate[:] = InvShiftRows(leakstate)
    end

    return state
end

mcattacktest(EQINVCIPHER,KL128,FORWARD,[(x,y,z)->mclfeqinvcipher(x,y,z,1),
                                        (x,y,z)->mclfeqinvcipher(x,y,z,2),
                                        (x,y,z)->mclfeqinvcipher(x,y,z,3),
                                        (x,y,z)->mclfeqinvcipher(x,y,z,4)])

mcxorattacktest(EQINVCIPHER,KL128,FORWARD,[(x,y,z)->mclfeqinvcipher(x,y,z,1,true),
                                           (x,y,z)->mclfeqinvcipher(x,y,z,2,true),
                                           (x,y,z)->mclfeqinvcipher(x,y,z,3,true),
                                           (x,y,z)->mclfeqinvcipher(x,y,z,4,true)])

