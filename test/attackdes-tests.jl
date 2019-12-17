# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Test

using Jlsca.Sca
using Jlsca.Trs
using Jlsca.Des

function testDesTraces(direction::Direction, analysis::Analysis, onetest::Bool=false, xor=false)
    tracedir = "../destraces"
    filenames = readdir(tracedir)

    for filename in filenames
        if filename[end-3+1:end] != "trs"
            continue
        end
        fullfilename = joinpath(tracedir,filename)
        print("file: $fullfilename\n")

        params = getParameters(fullfilename, direction)
        params.attack.xor = xor
        params.analysis = analysis

        # create Traces instance
        trs = InspectorTrace(fullfilename)

        key = getKey(params, sca(trs,params,1, 200))

        @test(key == params.knownKey)

        if onetest
          break
        end
    end
end

x = CPA()
x.leakages = [HW()]
@time testDesTraces(BACKWARD, x)
@time testDesTraces(FORWARD, CPA())
x.postProcessor = missing
@time testDesTraces(BACKWARD, CPA())
@time testDesTraces(FORWARD, CPA())

x = LRA()
x.basisModel = x -> basisModelSingleBits(x, 4)
@time testDesTraces(FORWARD, x, true)

@time testDesTraces(BACKWARD, CPA(), false, true)
@time testDesTraces(FORWARD, CPA(), false, true)


# WIP to replace tests above with tests below

function attacktester(attack,leaker,leakfuns,randfun=rand)
    key = rand(UInt8, keylength(attack))
    phases = numberOfPhases(attack)
    knownkeymaterial = Sca.correctKeyMaterial(attack,key)
    # @show bytes2hex(knownkeymaterial)
    phaseInput = Vector{Sca.unittype(attack)}(undef,0)

    for p in 1:phases
        input = randfun(UInt8, blocklength(attack))
        phaseDataOffset = offset(attack,p)
        phaseDataLength = numberOfTargets(attack, p)
        rkey = knownkeymaterial[phaseDataOffset+1:phaseDataOffset+phaseDataLength]

        if p > 1
            phaseInput = knownkeymaterial[1:phaseDataOffset]
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

function desleak(key,input,attack,leakfun,ismc=false)
    leakstate = BitVector(undef,64)
    mode = attack.mode
    encrypt = attack.encrypt
    direction = attack.direction

    if mode == DES
        c = encrypt ? Cipher : InvCipher
        w = Des.KeyExpansion(key)
    else
        error("FIXME")
    end

    output = c(input,w,(x,y)->leakfun(x,y,leakstate))
    data = direction == FORWARD ? input : output

    return output,toNibbles(leakstate),data
end

function sboxattacktest(mode,encrypt,direction,leakfuns)
    attack = DesSboxAttack()
    attack.mode = mode
    attack.encrypt = encrypt
    attack.direction = direction

    attacktester(attack,desleak,leakfuns) 
end

function roundattacktest(mode,encrypt,direction,leakfuns)
    attack = DesRoundAttack()
    attack.mode = mode
    attack.encrypt = encrypt
    attack.direction = direction

    attacktester(attack,desleak,leakfuns) 
end

function roundxorattacktest(mode,encrypt,direction,leakfuns)
    attack = DesRoundAttack()
    attack.mode = mode
    attack.encrypt = encrypt
    attack.direction = direction
    attack.xor = true

    attacktester(attack,desleak,leakfuns) 
end

function lf(label,state,leakstate,match)
    # print(label,"\t", bytes2hex(state),"\n")
    if label == match
        leakstate[1:length(state)] .= state
    end

    return state
end

# roundattacktest(DES,true,FORWARD,[(x,y,z)->lf(x,y,z,"r1.roundF"),(x,y,z)->lf(x,y,z,"r2.roundF")])

# roundxorattacktest(DES,true,FORWARD,[(x,y,z)->lf(x,y,z,"r1.roundinXORout"),(x,y,z)->lf(x,y,z,"r2.roundinXORout")])

# sboxattacktest(DES,true,FORWARD,[(x,y,z)->lf(x,y,z,"r1.sbox"),(x,y,z)->lf(x,y,z,"r2.sbox")])
# sboxattacktest(DES,false,FORWARD,[(x,y,z)->lf(x,y,z,"r16.sbox"),(x,y,z)->lf(x,y,z,"r15.sbox")])
# sboxattacktest(DES,true,BACKWARD,[(x,y,z)->lf(x,y,z,"r16.sbox"),(x,y,z)->lf(x,y,z,"r15.sbox")])
# sboxattacktest(DES,false,BACKWARD,[(x,y,z)->lf(x,y,z,"r1.sbox"),(x,y,z)->lf(x,y,z,"r2.sbox")])
