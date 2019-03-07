using Test
using Jlsca.Sca

function test()
	B = [5 5 4 5 5;
	     2 3 2 4 4;
	     1 1 0 3 4;
	     0 1 0 2 3]

	nX,nY = size(B)

	skea = SKEA(B)

	@test length(skea) == nX^nY

	solutions = collect(skea)

	@test length(solutions) == length(skea)

	@test length(unique(solutions)) == length(skea)

	ordered = map(y -> map(x -> B[y[x],x], eachindex(y)) |> sum, solutions)

	@test sort(ordered,rev=true) == ordered
end

test()
