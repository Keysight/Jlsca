
using Jlsca.Trs
using Test
using Printf

mutable struct MyNode
  count::Int
  one::MyNode
  zero::MyNode
  columns::Vector{Int}

  MyNode(c) = new(c)
end

function addMyNode(node::MyNode, bit ::Bool)
  local ret::MyNode

  node.count += 1
  if bit
    if !isdefined(node, :one)
      node.one = MyNode(0)
    end
    ret = node.one
  else
    if !isdefined(node, :zero)
      node.zero = MyNode(0)
    end
    ret = node.zero
  end

  return ret
end

function addColumn(root::MyNode, a::BitVector, idx::Int)
  node::MyNode = root
  for bit in a
    node = addMyNode(node, bit)
  end
  node.count += 1
  if !isdefined(node, :columns)
    node.columns = Vector{Int}()
  end
  push!(node.columns, idx)

  return node.count
end

function getNode(root::MyNode, a::BitVector)
  node::MyNode = root
  for bit in a
    if bit
      if !isdefined(node, :one)
        return nothing
      else
        node = node.one
      end
    else
      if !isdefined(node, :zero)
        return nothing
      else
        node = node.zero
      end
    end
  end

  return node
end

function createMatrix(r,c)
  a = BitArray(undef,r,c)
  (r,c) = size(a)
  for i in 1:c
    a[:,i] = rand(Bool, r)
  end
  return a
end

function test(a::BitArray{2})
  (r,c) = size(a)

  duplicateroot = MyNode(0)
  for i in 1:c
    addColumn(duplicateroot, a[:,i], i)
  end

  state = BitCompress(c)

  for i in 1:r
    bitcompress(state, a[i,:])
  end


  duplicates = state.duplicates
  inverses = state.inverses

  mask,lookup = toMaskAndLookup(state)

  reporteddupes = Vector{Int}()
  for i in 1:c
    if duplicates[i] != i
      @test !mask[i]
      push!(reporteddupes, i)
      push!(reporteddupes, duplicates[i])
    end
  end

  reportedinverses = Vector{Int}()
  for i in 1:c
    # if !(duplicates[i] == i && inverses[duplicates[i]] == i)
    if inverses[i] != i
      @test !mask[i]
      push!(reportedinverses, i)
      push!(reportedinverses, inverses[i])
      # push!(reportedinverses, inverses[duplicates[i]])
    end
  end

  for i in eachindex(mask)
    if mask[i]
      @test duplicates[i] == i || inverses[i] == i
    else
      @test duplicates[i] != i || inverses[i] != i
    end
  end

  for i in keys(lookup)
    @test mask[i]
    for j in lookup[i]
      @test i == j || !mask[j]
    end
  end

  @test reduce(union,values(lookup)) |> length == length(mask)

  for i in 1:c
    n = getNode(duplicateroot, a[:,i])
    if n.count > 1
      if !(i in reporteddupes)
        @printf("bad1: col %i has duplicates but not reported\n", i)
        @test !(i in reporteddupes)
      end
    else
      if (i in reporteddupes)
        @printf("bad2: col %i has no duplicates, but reported as duplicate\n", i)
        @test (i in reporteddupes)
      end      
    end
  end

  
  for i in 1:c
    n = getNode(duplicateroot, .~a[:,i])
    if n == nothing    
      if (i in reportedinverses)
        @printf("bad3: col %i has no inverse but reported as inverse\n", i)
        @test (i in reportedinverses)
      end
    else 
      if !(i in reportedinverses) && !(i in reporteddupes)
        @printf("bad4: col %i has inverse %s but not reported as inverse or duplicate\n", i, n.columns)
        @test !(i in reportedinverses) && !(i in reporteddupes)
      end      
    end
  end

 

end


function pretty(a::BitMatrix)
  (r,c) = size(a)
  for j in 1:c
    @printf("%4d", j)
  end
  @printf("\n")
  @printf("\n")
  for i in 1:r
    for j in 1:c
      @printf("%4d", a[i,j] ? 1 : 0)
    end
    @printf("\n")
  end
end

for i in 1:100
  a = createMatrix(rand(4:10),rand(10:20))
  # pretty(a)
  test(a)
end
