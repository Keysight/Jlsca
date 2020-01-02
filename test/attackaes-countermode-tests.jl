# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Test

using Jlsca.Sca
using Jlsca.Trs
using Jlsca.Aes

function aesleak(key,input,attack,leakfun)
    leakstate = zeros(UInt8,4,4)

    a = Int(attack.keyLength)
    c = Cipher
    w = KeyExpansion(key[1:a], keylength2Nr(a),keylength2Nk(a))

    output = c(input,w,(x,y)->leakfun(x,y,leakstate))

    return output,leakstate
end

function lf(label,state,leakstate,match,selection)
    # print(label,"\t", bytes2hex(state),"\n")
    if label == match
        leakstate .= state
        leakstate[1:length(selection)] = leakstate[selection]
    end

    return state
end

function attacktester(attack,key,iv,leaker,leakfuns,inputfun)
    phases = numberOfPhases(attack)
    keyiv = vcat(key,iv)
    knownkeymaterial = Sca.correctKeyMaterial(attack,keyiv)
    # @show bytes2hex(knownkeymaterial)
    phaseInput = Vector{Sca.unittype(attack)}(undef,0)

    for p in 1:phases
        input = inputfun(blocklength(attack), p)
        phaseDataOffset = offset(attack,p)
        phaseDataLength = numberOfTargets(attack, p)
        rkey = knownkeymaterial[phaseDataOffset+1:phaseDataOffset+phaseDataLength]

        if p > 1
            phaseInput = knownkeymaterial[1:phaseDataOffset]
        end

        if p > length(leakfuns)
            error("incomplete test!")
        end

        output,routput = leaker(keyiv,copy(input),attack,leakfuns[p])
        datapass = getDataPass(attack,p,phaseInput)
        rinput = datapass(copy(input))
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


function sboxcountermodeattacktest(keyLength,leakfuns)
    attack = AesCMForward(keyLength)
    refcounter = [UInt32(0)]
    iv = rand(UInt8,12)
    key = rand(UInt8,Int(keyLength))

    attacktester(attack,key,iv,aesleak,leakfuns,(x,y)->myinputgen(iv,refcounter,x,y)) 
end

function myinputgen(iv,refcounter,nbytes,phase)
    counter = refcounter[1] |> UInt32

    input = vcat(iv,reinterpret(UInt8,[hton(counter)]))

    refcounter[1] = counter + 1

    return input

end

const m = reshape(collect(1:16), (4,4))

sboxcountermodeattacktest(KL128,
    [
        (x,y,z)->lf(x,y,z,"r1.s_box",15:16),
        (x,y,z)->lf(x,y,z,"r2.s_box",1:8),
        (x,y,z)->lf(x,y,z,"r3.s_box",1:16),
        (x,y,z)->lf(x,y,z,"r4.s_box",1:16)
    ]
)

sboxcountermodeattacktest(KL192,
    [
        (x,y,z)->lf(x,y,z,"r1.s_box",15:16),
        (x,y,z)->lf(x,y,z,"r2.s_box",1:8),
        (x,y,z)->lf(x,y,z,"r3.s_box",1:16),
        (x,y,z)->lf(x,y,z,"r4.s_box",1:16),
        (x,y,z)->lf(x,y,z,"r5.s_box",1:8)
    ]
)

sboxcountermodeattacktest(KL256,
    [
        (x,y,z)->lf(x,y,z,"r1.s_box",15:16),
        (x,y,z)->lf(x,y,z,"r2.s_box",1:8),
        (x,y,z)->lf(x,y,z,"r3.s_box",1:16),
        (x,y,z)->lf(x,y,z,"r4.s_box",1:16),
        (x,y,z)->lf(x,y,z,"r5.s_box",1:16)
    ]
)
