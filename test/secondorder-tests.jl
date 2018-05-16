# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using Base.Test

using Jlsca.Trs

function naivesecondorder(s::SampleCombination, x::Vector)
    global y
    xl = length(x)
    y = zeros(Float64, div(xl * (xl-1),2))
    c = 1
    for i in 1:xl
        for j in i+1:xl
            y[c] = Trs.combine(s,x[i], x[j])
            c += 1
        end
    end     
    return y
end

function test1()
	samples = rand(Float64, 100)
	c = SecondOrderPass(AbsDiff())

	@test naivesecondorder(AbsDiff(),samples) == pass(c,samples,1)
end

function test3()
	samples = rand(Float64, 100)
	c = SecondOrderPass(AbsDiff())
	cols = 10

	naive = naivesecondorder(AbsDiff(),samples)
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

	@time a = naivesecondorder(AbsDiff(),samples)
	@time b = pass(c,samples,1) 
	@test a == b
end

test1()
test3()

perf1()
