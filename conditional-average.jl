# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Authors: Cees-Bart Breunesse, Ilya Kizhvatov
# Implements technique described in "Behind the Scene of Side Channel Attacks", Asiacrypt 2013 (see docs/cond_avg.pdf)

export CondAvg

import Base.get

type CondAvg <: Cond
  averages::Vector{Vector{Vector{Float64}}}
  counters::Matrix{UInt64}
  globcounter::Int

  function CondAvg(dataColumns, sampleLength, nrOfAverages)
    averagesType = Float64

    # a vector of vectors with vectors is fugly but much faster than a Matrix because these vectors are independent
    averages = Vector{Vector{Vector{averagesType}}}(dataColumns)
    for i in 1:dataColumns
        averages[i] = Vector{Vector{averagesType}}(nrOfAverages)
        for j in 1:nrOfAverages
            averages[i][j] = zeros(averagesType, sampleLength)
        end
    end
    counters = zeros(UInt64, dataColumns, nrOfAverages)
    @printf("Conditional averaging for max %d averages of %d samples per data offset, #threads %d\n", nrOfAverages, sampleLength, Threads.nthreads())
    new(averages, counters, 0)
  end
end

function add(c::CondAvg, datav::Vector, sample::Vector)
   Threads.@threads for d in eachindex(datav)
        data = datav[d]
        c.counters[d, data + 1] += 1
        counter = c.counters[d,data + 1]

        # nice and short but slow
        # a = c.averages[d][data + 1]
        # c.averages[d][data + 1] = a .+ (sample .- a) ./ counter

        # looped and ugly but fast ..
        for i in 1:length(sample)
          a = c.averages[d][data + 1][i]
          c.averages[d][data + 1][i] = a + (Float64(sample[i]) - a) / counter
        end
    end
    c.globcounter += 1
end

function get(c::CondAvg)
  datas = Matrix[]
  averages = Matrix[]

  if size(c.counters)[2] <= 2^8
    dataType = UInt8
  elseif size(c.counters)[2] <= 2^16
    dataType = UInt16
  else
    throw(Exception("Unsupported and not recommended ;)"))
  end

  for i in 1:size(c.counters)[1]
    dataSnap = find(c.counters[i,:])
    sampleSnap = reduce(hcat,c.averages[i][dataSnap])'
    dataSnap = dataSnap .- 1
    dataSnap = reshape(convert(Array{dataType,1}, dataSnap), length(dataSnap),1)
    push!(datas, dataSnap)
    push!(averages, sampleSnap)
  end

  @printf("\nAveraged %d input traces, %s data type, %s sample type\n", c.globcounter, string(dataType), string(eltype(averages[1])))


  return (datas,averages)
end

function getCounter(c::CondAvg)
  return c.globcounter
end
