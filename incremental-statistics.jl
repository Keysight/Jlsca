# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse
#
# Implements algorithms from this fine Sandia paper:
# http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.214.8508&rep=rep1&type=pdf

type IncrementalMeanVariance
  mean::Vector{Float64}
  var::Vector{Float64}
  n::Int

  function IncrementalMeanVariance(x::Int)
    new(zeros(Float64, x), zeros(Float64, x), 0)
  end
end

function add!(state::IncrementalMeanVariance, data::Vector, y1::Vector=data.-state.mean)
  state.n += 1
  @inbounds for x in eachindex(state.mean)
    state.mean[x] = state.mean[x] + (data[x] - state.mean[x]) / state.n
    y2 = data[x] - state.mean[x]
    state.var[x] = state.var[x] + y1[x] * y2
  end
end

function add!(this::IncrementalMeanVariance, other::IncrementalMeanVariance)
  n = this.n + other.n
  delta = other.mean .- this.mean
  this.mean = this.mean .+ other.n * delta ./n
  this.var = this.var .+ other.var + this.n*other.n*delta.^2/n
  this.n = n
end

function getVariance(state::IncrementalMeanVariance)
  return 1/(state.n - 1) .* state.var
end

function getStdDev(state::IncrementalMeanVariance)
  return sqrt(getVariance(state))
end

type IncrementalCovariance
  meanVarX::IncrementalMeanVariance
  meanVarY::IncrementalMeanVariance
  cov::Matrix{Float64}
  n::Int

  function IncrementalCovariance(numberOfX::Int, numberOfY::Int)
    IncrementalCovariance(IncrementalMeanVariance(numberOfX), IncrementalMeanVariance(numberOfY))
  end

  function IncrementalCovariance(meanVarX::IncrementalMeanVariance, meanVarY::IncrementalMeanVariance)
    new(meanVarX, meanVarY, zeros(Float64, (length(meanVarX.mean), length(meanVarY.mean))), 0)
  end
end

function add!(state::IncrementalCovariance, dataX::Vector, dataY::Vector, dataXn::Vector=dataX.-state.meanVarX.mean, updateMeanX::Bool=true, dataYn::Vector=dataY.-state.meanVarY.mean, updateMeanY::Bool=true)
  @assert((length(dataX),length(dataY)) == size(state.cov))

  state.n += 1
  n = state.n
  @inbounds for y in eachindex(dataYn)
    dataYny = dataYn[y]
    for x in eachindex(dataXn)
      state.cov[x,y] += (n-1)/n * dataXn[x]*dataYny
    end
  end

  if updateMeanX
    add!(state.meanVarX, dataX, dataXn)
  end

  if updateMeanY
    add!(state.meanVarY, dataY, dataYn)
  end
end

function add!(this::IncrementalCovariance, other::IncrementalCovariance, updateMeanX::Bool=true, updateMeanY::Bool=true)
  deltaX = this.meanVarX.mean .- other.meanVarX.mean
  deltaY = this.meanVarY.mean .- other.meanVarY.mean
  n = this.n + other.n
  @inbounds for y in eachindex(deltaY)
    for x in eachindex(deltaX)
      this.cov[x,y] = this.cov[x,y] .+ other.cov[x,y] + (this.n*other.n^2 + other.n*this.n^2) / n^2 .* deltaX[x] .* deltaY[y]
    end
  end

  this.n = this.n + other.n

  if updateMeanX
    add!(this.meanVarX, other.meanVarX)
  end

  if updateMeanY
    add!(this.meanVarY, other.meanVarY)
  end
end

function getCov(state::IncrementalCovariance)
  return 1/(state.n-1) .* state.cov
end

function getCorr(state::IncrementalCovariance)
  corr = similar(state.cov)

  xstddev = getStdDev(state.meanVarX)
  ystddev = getStdDev(state.meanVarY)

  for y in 1:size(corr)[2]
    for x in 1:size(corr)[1]
      corr[x,y] = 1/(state.n-1) * state.cov[x,y] / (xstddev[x] * ystddev[y])
    end
  end

  return corr
end

function getScoresAndOffsets(state::IncrementalCovariance, reducer::Function)
  scores = zeros(Float64, size(state.cov)[2])
  offsets = zeros(Int, size(state.cov)[2])
  corrCol = zeros(Float64, size(state.cov)[1])

  xstddev = getStdDev(state.meanVarX)
  ystddev = getStdDev(state.meanVarY)

  for y in 1:size(corr)[2]
    for x in 1:size(corr)[1]
      corrCol[x] = 1/(state.n-1) * state.cov[x,y] / (xstddev[x] * ystddev[y])
    end
    (score,offset) = reducer(corColl)
    scores[y] = score
    offsets[y] = offset
  end

  return (scores,offsets)
end
