# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test

using ProgressMeter
using Jlsca.Trs

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
    @test_approx_eq mean(x[:,c]) meanVarX.mean[c]
    @test_approx_eq mean(y[:,c]) meanVarY.mean[c]
    @test_approx_eq var(y[:,c]) getVariance(meanVarY)[c]
    @test_approx_eq var(x[:,c]) getVariance(meanVarX)[c]
  end

  @test_approx_eq cov(x,y) getCov(covXY)
  @test_approx_eq cor(x,y) getCorr(covXY)

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
    add!(meanVarX, x[r,:], xmean)
  end

  for c in 1:size(x)[2]
    @test_approx_eq mean(x[:,c]) meanVarX.mean[c]
    @test_approx_eq mean(y[:,c]) meanVarY.mean[c]
    @test_approx_eq var(y[:,c]) getVariance(meanVarY)[c]
    @test_approx_eq var(x[:,c]) getVariance(meanVarX)[c]
  end

  @test_approx_eq cov(x,y) getCov(covXY)
  @test_approx_eq cor(x,y) getCorr(covXY)

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

  range1 = 1:div(size(x)[1],2)
  range2 = div(size(x)[1],2)+1:size(x)[1]
  @printf("range1 %s, range2 %s\n", range1, range2)

  for r in range1
    add!(covXY1, x[r,:], y[r,:])
    add!(covXY3, x[r,:], y[r,:])
  end

  for r in range2
    add!(covXY2, x[r,:], y[r,:])
    add!(covXY3, x[r,:], y[r,:])
  end

  add!(covXY1, covXY2)

  for c in 1:size(x)[2]
    @test_approx_eq mean(x[:,c]) meanVarX1.mean[c]
    @test_approx_eq mean(y[:,c]) meanVarY1.mean[c]
    @test_approx_eq var(y[:,c]) getVariance(meanVarY1)[c]
    @test_approx_eq var(x[:,c]) getVariance(meanVarX1)[c]
  end

  @test_approx_eq cov(x,y) getCov(covXY1)
  @test_approx_eq cor(x,y) getCorr(covXY1)

  @test_approx_eq getCov(covXY3) getCov(covXY1)
  @test_approx_eq getCorr(covXY3) getCorr(covXY1)
end

function speedtest()
  rows = 10000
  nrX = 512
  nrY = 8*256*16

  meanVarX = IncrementalMeanVariance(nrX)
  meanVarY = IncrementalMeanVariance(nrY)
  covXY = IncrementalCovariance(meanVarX, meanVarY)

  for r in 1:rows
    x = rand(Float64, nrX)
    y = rand(Float64, nrY)
    add!(covXY, x, y)
  end

  # Profile.print(maxdepth=12,combine=true)

  return covXY
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

  # Profile.print(maxdepth=12,combine=true)
end

test1()
test1n()
test2()
# @time speedtest()
# @time meanspeedtest1()
