# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test

using Jlsca.Trs

function test1()
	samples = rand(Float64, 100)
	c = SecondOrderPass(AbsDiff())

	@test Trs.naivesecondorder(AbsDiff(),samples) == pass(c,samples,1)
end

function test3()
	samples = rand(Float64, 100)
	c = SecondOrderPass(AbsDiff())
	cols = 10

	naive = Trs.naivesecondorder(AbsDiff(),samples)
	nl = length(naive)

	for i in 1:div(nl+cols-1,cols)
		l = (i-1)*cols+1
		u = min(i*cols,nl)
		# print("col $i\n")
		@test naive[l:u] == pass(c,samples,1,l:u)
	end

end

function perf1() 
	samples = rand(Float64, 10000)
	c = SecondOrderPass(AbsDiff())

	@time a = Trs.naivesecondorder(AbsDiff(),samples)
	@time b = pass(c,samples,1) 
	@test a == b
end

test1()
test3()

perf1()
