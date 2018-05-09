# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
# Author: Cees-Bart Breunesse

using Jlsca.Trs
using Jlsca.Sca

using Base.Test

function SNRnaive(trs::Trace, r::Range)
    (somedata,somesamples) = trs[1]
    nrTargets = length(somedata)
    nrSamples = length(somesamples)
    targetType = eltype(somedata)
    
    mvs = Dict{Int,Dict{targetType,IncrementalMeanVariance}}()
    
    for t in r
        (data,samples) = trs[t]
        if length(data) == 0 || length(samples) == 0
            continue
        end
        for c in 1:nrTargets
            if !(c in keys(mvs))
                mvs[c] = Dict{targetType,IncrementalMeanVariance}()
            end
            
            d = data[c]
            
            if !(d in keys(mvs[c]))
                mvs[c][d] = IncrementalMeanVariance(nrSamples)
            end
            
            add!(mvs[c][d], samples)
        end
    end
    
    noise = [IncrementalMeanVariance(nrSamples) for c in 1:nrTargets]
    signals = [IncrementalMeanVariance(nrSamples) for c in 1:nrTargets]

    for t in r
        (data,samples) = trs[t]
        if length(data) == 0 || length(samples) == 0
            continue
        end
        for c in 1:nrTargets
            d = data[c]
            
            add!(noise[c], samples .- mvs[c][d].mean)
            add!(signals[c], mvs[c][d].mean)
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

function mytest() 
    numTraces = 100000
    numSamples = 10
    data = rand(UInt8, numTraces,1)
    samples = rand(Float32, numTraces,numSamples)
    trs = InMemory(data,samples)
    addDataPass(trs, x -> hw.(x))

    snr1 = SNRnaive(trs, 1:numTraces)

    snr2 = SNR(trs, 1:numTraces)

    @test snr1[1] ≈ snr2[1]
    @test snr1[2] ≈ snr2[2]
end

mytest()

function myprofile() 
    numTraces = 100000
    numSamples = 10000
    data = rand(UInt8, numTraces,1)
    samples = rand(Float32, numTraces,numSamples)
    trs = InMemory(data,samples)
    addDataPass(trs, x -> hw.(x))

    Profile.clear_malloc_data()
    Profile.start_timer()
    snr2 = SNR(trs, 1:numTraces)
    Profile.print(maxdepth=16,combine=true)

end

# myprofile()