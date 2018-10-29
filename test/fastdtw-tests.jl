using Test

using Jlsca.Align
import Jlsca.Align:expandwindow,dtw,full,MySparseMatrix

function test0()
  dims = (4,4)
  path = [1,6,11,16]
  radius = 0
  window = expandwindow(path, dims, 2 .* dims, radius)

  answer = 
  [1  2
   1  3
   2  4
   3  5
   4  6
   5  7
   6  8
   7  8]

  @test window == answer

  dims = (8,8)

  path = map(x -> (LinearIndices(dims))[x...], [(1,1),(2,1),(3,2),(4,3),(5,4),(5,5),(5,6),(6,7),(7,8),(8,8)])
  radius = 0
  window = expandwindow(path, dims, 2 .* dims, radius)

  answer = 
  [ 1   4
    1   5
    4   6
    5   7
    6   8
    7   9
    8  10
    9  10
    9  10
    9  10
    9  10
    9  11
   10  12
   11  13
   12  16
   13  16]

  @test window == answer

  window = expandwindow(path, dims, 2 .* dims, 1)

  answer = [
       1   6
    1   7
    1   8
    3   9
    4  10
    5  11
    6  11
    7  11
    8  11
    8  11
    8  12
    8  13
    8  14
    9  16
   10  16
   11  16
  ]

  @test window == answer
end

function test1()
  answer = [
  4.0   5.0   6.0  10.0  19.0
 13.0   8.0   9.0  15.0  26.0
 29.0  17.0  17.0  25.0  40.0
 33.0  18.0  18.0  21.0  30.0
 37.0  19.0  19.0  22.0  30.0]

  X = [3,4,5,3,3]
  Y = [1,2,2,1,0]
  window = zeros(Int,length(Y),2)
  window[:,1] .= 1
  window[:,2] .= length(X)
  # window[3,:] = [3,3]
  cost = MySparseMatrix{Float64}((length(X),length(Y)),window)
  path = dtw(X,Y,window,cost)
  # @show map(x -> ind2sub((length(X),length(Y)),x), path)
  @test full(cost) == answer
  # @show cost
end

function test2()
  answer = [4.0 5.0  0.0  4.0 13.0; 
          13.0  8.0  0.0 13.0 20.0; 
          29.0 17.0 17.0 29.0 38.0; 
          33.0 18.0  0.0 21.0 30.0; 
          37.0 19.0  0.0 25.0 30.0]

  X = [3,4,5,3,3]
  Y = [1,2,2,1,0]
  window = zeros(Int,length(Y),2)
  window[:,1] .= 1
  window[:,2] .= length(X)
  window[3,:] .= [3,3]
  cost = MySparseMatrix{Float64}((length(X),length(Y)),window)
  path = dtw(X,Y,window,cost)
  # @show map(x -> ind2sub((length(X),length(Y)),x), path)
  # @show cost.cols[3]
  @test full(cost) == answer
  # @code_warntype getindex(cost,1,1)
  # @code_warntype setindex!(cost,1.0,1,1)
  # @code_warntype dtw(X,Y,length(X),length(Y),window)
  # @code_warntype mymin(3.1,2.3,3.1)
end

function speedtest1()
  nsamples = 1500
  X = rand(Float64, nsamples)
  nrrows = 100

  for i in 1:nrrows
    Y = rand(Float64, nsamples)
    path = dtw(X,Y)
    # Ya = align(Y,path,length(X),length(Y))
  end
end

function speedtest2()
  nsamples = 15000
  X = rand(Float64, nsamples)
  nrrows = 100

  for i in 1:nrrows
    Y = rand(Float64, nsamples)
    path = fastdtw(X,Y,90)
    Ya = align(Y,path,length(X),length(Y))
  end
end

test0()
test1()
test2()

# using Profile

# @time speedtest1()
# @time speedtest1()
# Profile.clear_malloc_data()
# @profile speedtest1()
# Profile.print(maxdepth=12,combine=true,format=:tree)