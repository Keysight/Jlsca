# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
# Author: Cees-Bart Breunesse

# Implements SNR as described in https://www.springer.com/us/book/9780387308579

using ProgressMeter
using ..Trs


function addme(mvs::Dict, data::Vector{N}, samples::Vector) where {N}
    if length(data) == 0 || length(samples) == 0
        return
    end

    nrSamples = length(samples)
    nrTargets = length(data)
    
    for c in 1:nrTargets
        if !(c in keys(mvs))
            mvs[c] = Dict{N,IncrementalMeanVariance}()
        end
        
        d = data[c]
        
        if !(d in keys(mvs[c]))
            mvs[c][d] = IncrementalMeanVariance(nrSamples)
        end
        
        add!(mvs[c][d], samples)
    end
end

export SNR

"""
Computes the SNR using the data values in a trace set as distinghuishers. 

# Example

```
addDataPass(trs, x -> x[1:2])
s,r = SNR(trs, 1:length(trs))
snr = s ./ r
plot(snr)
```
"""
function SNR(trs::Trace, r::Range)
    mvs = Dict()
    
    @showprogress 1 "Computing SNR ..."  for t in r
        (data,samples) = trs[t]
        addme(mvs,data,samples)
    end

    nrTargets = length(keys(mvs))
    nrSamples = length(first((first(mvs)[2]))[2].mean)
    
    noise = [IncrementalMeanVariance(nrSamples) for c in 1:nrTargets]
    signals = [IncrementalMeanVariance(nrSamples) for c in 1:nrTargets]
    
    for c in 1:nrTargets
        ds = sort(collect(keys(mvs[c])))
        for d in 1:length(ds)
            copy1 = deepcopy(mvs[c][ds[d]])
            copy1.mean .= 0
            add!(noise[c],copy1)
            copy2 = deepcopy(mvs[c][ds[d]])
            copy2.var .= 0
            add!(signals[c],copy2)
        end
    end
    
    signalvariance = Matrix{Float64}(nrSamples,nrTargets)
    noisevariance = Matrix{Float64}(nrSamples,nrTargets)
    
    for c in 1:nrTargets
        signalvariance[:,c] = getVariance(signals[c]) 
        noisevariance[:,c] = getVariance(noise[c]) 
    end 
    
    return signalvariance,noisevariance
end

function SNR(trs::Trace, r::Range, attack::Attack, key::Vector{UInt8}, leakages::Vector{Leakage})
    phases = 1:numberOfPhases(attack)

    return mapreduce(phase -> SNR(trs,r,attack,key,leakages,phase), (x,y) -> (hcat(x[1],y[1]),hcat(x[2],y[2])), phases)
end

function SNR(trs::Trace, r::Range, attack::Attack, key::Vector{UInt8}, leakages::Vector{Leakage}, phase::Int)
    return SNR(trs,r,attack,key,leakages,phase,collect(1:numberOfTargets(attack,phase)))
end

function SNR(trs::Trace, r::Range, attack::Attack, key::Vector{UInt8}, leakages::Vector{Leakage}, phase::Int, targetOffsets::Vector{Int})
    phaseDataOffset = offset(attack,phase)
    phaseDataLength = numberOfTargets(attack, phase)
    allkeymaterial = Sca.correctKeyMaterial(attack, key)
    kb = allkeymaterial[phaseDataOffset+1:phaseDataOffset+phaseDataLength][targetOffsets]
    targets = getTargets(attack, phase, allkeymaterial)[targetOffsets]
    datapass = getDataPass(attack, phase, allkeymaterial)

    if !isnull(datapass)
        addDataPass(trs, get(datapass))
    end

    addDataPass(trs, x -> x[targetOffsets])
        
    addDataPass(trs, x -> map(y -> target(targets[y], x[y], kb[y]), 1:length(x)))

    addDataPass(trs, x -> mapreduce(y -> map(z -> leak(leakages[z], x[y]), 1:length(leakages)), vcat, 1:length(x)))
    
    snrs = SNR(trs, r)
    
    popDataPass(trs)

    popDataPass(trs)

    popDataPass(trs)

    if !isnull(datapass)
        popDataPass(trs)
    end
    
    return snrs
end
