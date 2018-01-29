# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test

using ProgressMeter
using Jlsca.Sca

# normal usage
function test1()
  x = rand(Float64, (100, 20))
  y = rand(Float64, (100, 20))

  meanVarX = IncrementalMeanVariance(size(x)[2])
  meanVarY = IncrementalMeanVariance(size(y)[2])
  covXY = IncrementalCovariance(meanVarX, meanVarY)

  for r in 1:size(x)[1]
    add!(covXY, x[r,:], y[r,:])
  end

  for c in 1:size(x)[2]
    @test mean(x[:,c]) ≈ meanVarX.mean[c]
    @test mean(y[:,c]) ≈ meanVarY.mean[c]
    @test var(y[:,c]) ≈ getVariance(meanVarY)[c]
    @test var(x[:,c]) ≈ getVariance(meanVarX)[c]
  end

  @test cov(x,y) ≈ getCov(covXY)
  @test cor(x,y) ≈ getCorr(covXY)

end


# combining means
function testmeanadd()
  x = rand(Float64, (100, 20))
  y = rand(Float64, (200, 20))
  z = rand(Float64, (300, 20))

  meanVarX = IncrementalMeanVariance(size(x)[2])
  meanVarY = IncrementalMeanVariance(size(y)[2])
  meanVarZ = IncrementalMeanVariance(size(y)[2])

  for r in 1:size(x)[1]
    add!(meanVarX, x[r,:])
  end

  for r in 1:size(y)[1]
    add!(meanVarY, y[r,:])
  end

  for r in 1:size(z)[1]
    add!(meanVarZ, z[r,:])
  end

  add!(meanVarX, meanVarY)
  add!(meanVarX, meanVarZ)

  xyz = vcat(x,y,z)

  for c in 1:size(xyz)[2]
    @test mean(xyz[:,c]) ≈ meanVarX.mean[c]
    @test var(xyz[:,c]) ≈ getVariance(meanVarX)[c]
  end
end

# normal usage, tiled
function test1tiled()
  x = rand(Float64, (100, 20))
  y = rand(Float64, (100, 20))

  meanVarX = IncrementalMeanVariance(size(x)[2])
  meanVarY = IncrementalMeanVariance(size(y)[2])
  covXY = IncrementalCovarianceTiled(meanVarX, meanVarY, 5, 5, 3)

  for r in 1:size(x)[1]
    add!(covXY, x[r,:], y[r,:])
  end

  for c in 1:size(x)[2]
    @test mean(x[:,c]) ≈ meanVarX.mean[c]
    @test mean(y[:,c]) ≈ meanVarY.mean[c]
    @test var(y[:,c]) ≈ getVariance(meanVarY)[c]
    @test var(x[:,c]) ≈ getVariance(meanVarX)[c]
  end

  @test cov(x,y) ≈ getCov(covXY)
  @test cor(x,y) ≈ getCorr(covXY)

end

# normal usage, but mean of X computed outside the add!(covXY,..) function
function test1n()
  x = rand(Float64, (1000, 20))
  y = rand(Float64, (1000, 25))

  meanVarX = IncrementalMeanVariance(size(x)[2])
  meanVarY = IncrementalMeanVariance(size(y)[2])
  covXY = IncrementalCovariance(meanVarX, meanVarY)

  for r in 1:size(x)[1]
    xmean = x[r,:] .- meanVarX.mean
    ymean = y[r,:] .- meanVarY.mean
    add!(covXY, x[r,:], y[r,:], xmean, false, ymean, true)
    add!(meanVarX, x[r,:])
  end

  for c in 1:size(x)[2]
    @test mean(x[:,c]) ≈ meanVarX.mean[c]
    @test mean(y[:,c]) ≈ meanVarY.mean[c]
    @test var(y[:,c]) ≈ getVariance(meanVarY)[c]
    @test var(x[:,c]) ≈ getVariance(meanVarX)[c]
  end

  @test cov(x,y) ≈ getCov(covXY)
  @test cor(x,y) ≈ getCorr(covXY)

end

# normal usage, but mean of X computed outside the add!(covXY,..) function
function test1ntiled()
  x = rand(Float64, (1000, 20))
  y = rand(Float64, (1000, 25))

  meanVarX = IncrementalMeanVariance(size(x)[2])
  meanVarY = IncrementalMeanVariance(size(y)[2])
  covXY = IncrementalCovarianceTiled(meanVarX, meanVarY,4,4,3)

  for r in 1:size(x)[1]
    xmean = x[r,:] .- meanVarX.mean
    ymean = y[r,:] .- meanVarY.mean
    add!(covXY, x[r,:], y[r,:], xmean, false, ymean, true)
    add!(meanVarX, x[r,:])
  end

  for c in 1:size(x)[2]
    @test mean(x[:,c]) ≈ meanVarX.mean[c]
    @test mean(y[:,c]) ≈ meanVarY.mean[c]
    @test var(y[:,c]) ≈ getVariance(meanVarY)[c]
    @test var(x[:,c]) ≈ getVariance(meanVarX)[c]
  end

  @test cov(x,y) ≈ getCov(covXY)
  @test cor(x,y) ≈ getCorr(covXY)

end

# combining covariances
function test2()
  x = rand(Float64, (500, 200))
  y = rand(Float64, (500, 205))

  meanVarX1 = IncrementalMeanVariance(size(x)[2])
  meanVarY1 = IncrementalMeanVariance(size(y)[2])
  covXY1 = IncrementalCovariance(meanVarX1, meanVarY1)

  meanVarX2 = IncrementalMeanVariance(size(x)[2])
  meanVarY2 = IncrementalMeanVariance(size(y)[2])
  covXY2 = IncrementalCovariance(meanVarX2, meanVarY2)

  meanVarX3 = IncrementalMeanVariance(size(x)[2])
  meanVarY3 = IncrementalMeanVariance(size(y)[2])
  covXY3 = IncrementalCovariance(meanVarX3, meanVarY3)

  meanVarX = IncrementalMeanVariance(size(x)[2])
  meanVarY = IncrementalMeanVariance(size(y)[2])
  covXY = IncrementalCovariance(meanVarX, meanVarY)

  range1 = 1:50
  range2 = 51:200
  range3 = 201:500
  @printf("range1 %s, range2 %s, range3 %s\n", range1, range2, range3)

  for r in range1
    add!(covXY1, x[r,:], y[r,:])
    add!(covXY, x[r,:], y[r,:])
  end

  for r in range2
    add!(covXY2, x[r,:], y[r,:])
    add!(covXY, x[r,:], y[r,:])
  end

  for r in range3
    add!(covXY3, x[r,:], y[r,:])
    add!(covXY, x[r,:], y[r,:])
  end

  add!(covXY1, covXY2)
  add!(covXY1, covXY3)

  for c in 1:size(x)[2]
    @test mean(x[:,c]) ≈ meanVarX1.mean[c] ≈ meanVarX.mean[c]
    @test mean(y[:,c]) ≈ meanVarY1.mean[c] ≈ meanVarY.mean[c]
    @test var(y[:,c]) ≈ getVariance(meanVarY1)[c]≈ getVariance(meanVarY)[c]
    @test var(x[:,c]) ≈ getVariance(meanVarX1)[c] ≈ getVariance(meanVarX)[c]
  end

  @test cov(x,y) ≈ getCov(covXY1)
  @test cor(x,y) ≈ getCorr(covXY1)

  @test getCov(covXY) ≈ getCov(covXY1)
  @test getCorr(covXY) ≈ getCorr(covXY1)
end

# combining covariances
function test2tiled()
  x = rand(Float64, (500, 200))
  y = rand(Float64, (500, 205))

  meanVarX1 = IncrementalMeanVariance(size(x)[2])
  meanVarY1 = IncrementalMeanVariance(size(y)[2])
  covXY1 = IncrementalCovarianceTiled(meanVarX1, meanVarY1)

  meanVarX2 = IncrementalMeanVariance(size(x)[2])
  meanVarY2 = IncrementalMeanVariance(size(y)[2])
  covXY2 = IncrementalCovarianceTiled(meanVarX2, meanVarY2)

  meanVarX3 = IncrementalMeanVariance(size(x)[2])
  meanVarY3 = IncrementalMeanVariance(size(y)[2])
  covXY3 = IncrementalCovarianceTiled(meanVarX3, meanVarY3)

  meanVarX = IncrementalMeanVariance(size(x)[2])
  meanVarY = IncrementalMeanVariance(size(y)[2])
  covXY = IncrementalCovarianceTiled(meanVarX, meanVarY)

  range1 = 1:50
  range2 = 51:200
  range3 = 201:500
  @printf("range1 %s, range2 %s, range3 %s\n", range1, range2, range3)

  for r in range1
    add!(covXY1, x[r,:], y[r,:])
    add!(covXY, x[r,:], y[r,:])
  end

  for r in range2
    add!(covXY2, x[r,:], y[r,:])
    add!(covXY, x[r,:], y[r,:])
  end

  for r in range3
    add!(covXY3, x[r,:], y[r,:])
    add!(covXY, x[r,:], y[r,:])
  end

  add!(covXY1, covXY2)
  add!(covXY1, covXY3)

  for c in 1:size(x)[2]
    @test mean(x[:,c]) ≈ meanVarX1.mean[c] ≈ meanVarX.mean[c]
    @test mean(y[:,c]) ≈ meanVarY1.mean[c] ≈ meanVarY.mean[c]
    @test var(y[:,c]) ≈ getVariance(meanVarY1)[c]≈ getVariance(meanVarY)[c]
    @test var(x[:,c]) ≈ getVariance(meanVarX1)[c] ≈ getVariance(meanVarX)[c]
  end

  @test cov(x,y) ≈ getCov(covXY1)
  @test cor(x,y) ≈ getCorr(covXY1)

  @test getCov(covXY) ≈ getCov(covXY1)
  @test getCorr(covXY) ≈ getCorr(covXY1)
end

function speedtest(rows, nrX, nrY)

  meanVarX = IncrementalMeanVariance(nrX)
  meanVarY = IncrementalMeanVariance(nrY)
  covXY = IncrementalCovariance(meanVarX, meanVarY)

  for r in 1:rows
    x = rand(Float64, nrX)
    y = rand(Float64, nrY)
    add!(covXY, x, y)
  end

  # Profile.print(maxdepth=12,combine=true)

  return getCorr(covXY)
end

using Base.Threads

function speedtesttiled(rows, nrX, nrY, tilesX, tilesY,cache)

  meanVarX = IncrementalMeanVariance(nrX)
  meanVarY = IncrementalMeanVariance(nrY)
  covXY = IncrementalCovarianceTiled(meanVarX, meanVarY, tilesX, tilesY, cache)

  for r in 1:rows
    x = rand(Float64, nrX)
    y = rand(Float64, nrY)
    add!(covXY, x, y)
  end

  # Profile.print(maxdepth=12,combine=true)

  return getCorr(covXY)
end

function dumpasm()
  c = Array(Float64,3,5)
  x = rand(Float64, 10)
  y = rand(Float64, 10)

  @code_warntype Trs.updateCov!(c, x, 1, 10, y, 1, 10, 0.9)
  @code_native Trs.updateCov!(c, x, 1, 10, y, 1, 10, 0.9)

end

function bla()
  nrX = 4
  nrY = 5

  meanVarX = IncrementalMeanVariance(nrX)
  meanVarY = IncrementalMeanVariance(nrY)
  covXY = IncrementalCovariance(meanVarX, meanVarY)

  add!(covXY, [2.0,2.0,3.0,4.0], [5.0,6.0,7.0,8.0,9.0])

  println(covXY.cov)
end

function meanspeedtest1()
  rows = 10000
  nrX = 512
  nrY = 8*256*16

  meanVarX = IncrementalMeanVariance(nrX)
  meanVarY = IncrementalMeanVariance(nrY)

  for r in 1:rows
    x = rand(Float64, nrX)
    y = rand(Float64, nrY)

    normalX = x .- meanVarX.mean
    normalY = y .- meanVarY.mean
    add!(meanVarX, x, normalX)
    add!(meanVarY, y, normalY)
  end

end

test1tiled()
test1ntiled()
test2tiled()

test1()
testmeanadd()
test1n()
test2()

const rows = 500
const nrX = 1500
const nrY = 16*8*256
const tilesX = 128
const tilesY = 128
const cache = 32

# @time speedtest(rows,nrX,nrY)
# @time speedtest(rows,nrX,nrY)
# @time speedtesttiled(rows,nrX,nrY,tilesX,tilesY,cache)
# @time speedtesttiled(rows,nrX,nrY,tilesX,tilesY,cache)

# dumpasm()