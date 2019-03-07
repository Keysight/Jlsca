# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse
#
# Implements FastDTW [1] and uses the warp path for alignment of traces [2].
# 
# [1] https://pdfs.semanticscholar.org/05a2/0cde15e172fc82f32774dd0cf4fe5827cad2.pdf
# [2] https://pdfs.semanticscholar.org/aceb/7c307098a414d7c384d6189226e4375cf02d.pdf
# 
# see ?fastdtw down this file on how to use it

@inline dist(x,y) = (x-y)^2

function warppath(c,window)
    dims = size(c)
    n = length(c)
    path = Vector{Int}(undef,dims[1] + dims[2])
    p = 1
    path[p] = n

    # l2 | l3
    # -------
    # l1 | c
    
    linidxes = LinearIndices(dims)
    cartindxes = CartesianIndices(dims)

    while n != 1
        x,y = Tuple(cartindxes[n])
        lowerX = window[y,1]
        upperX = window[y,2]
        if y > 1
            leftlowerX = window[y-1,1]
            leftupperX = window[y-1,2]
            if leftlowerX <= x <= leftupperX
                l1 = c.cols[y-1][x-leftlowerX+1]
            else
                l1 = Inf
            end
            if leftlowerX <= x-1 <= leftupperX
                l2 = c.cols[y-1][x-1-leftlowerX+1]
            else
                l2 = Inf
            end
        else
            l1 = Inf
            l2 = Inf
        end

        if x == lowerX
            l3 = Inf
        else
            l3 = c.cols[y][x-1-lowerX+1]
        end

        if l1 < l2
            nextx = x
            nexty = y-1
            smallest = l1
        else 
            nextx = x-1
            nexty = y-1
            smallest = l2
        end

        if l3 < smallest
            nextx = x-1
            nexty = y
        end

        n = linidxes[nextx,nexty]
        p += 1
        path[p] = n
    end
    return reverse!(resize!(path, p))
end

function defaultwindow(nX,nY)
    window = zeros(Int,nY,2)
    window[:,1] .= 1
    window[:,2] .= nX
    return window
end

struct MySparseMatrix{T} <: AbstractArray{T,2} 
    window::Matrix{Int}
    cols::Vector{Vector{T}}
    dims::Tuple{Int,Int}

    function MySparseMatrix{T}(arraydims,window) where T
        dims = size(window)
        cols = Vector{Vector{T}}(undef,dims[1])
        for y in 1:dims[1]
            cols[y] = Vector{T}(undef,window[y,2] - window[y,1] + 1)
            cols[y] .= Inf
        end
        new(window,cols,arraydims)
    end
end

import Base.getindex

# this code is slow and not used in this module. It's used if 
# someone calls dtw, passes a MySparseMatrix and wishes to, after
# dtw returns, access the matrix as a normal matrix
function getindex(c::MySparseMatrix{T}, x::Int64, y::Int64) where T
    Y = c.cols

    checkbounds(Bool,Y,y) || throw(BoundsError(c, (x,y)))
    checkindex(Bool,1:c.dims[1],x) || throw(BoundsError(c, (x,y)))

    xoff = x - c.window[y,1] + 1
    if 1 <= xoff <= length(c.cols[y])
        X = Y[y]
        return X[xoff]
    else
        zero(T)
    end
end

import Base.size

function size(c::MySparseMatrix{Float64})
    return c.dims
end

import Base.length 

length(c::MySparseMatrix{Float64}) = c.dims[1] * c.dims[2]

# import Base.full

function full(a::MySparseMatrix{T}) where T
    b = Matrix{T}(undef,size(a))
    xs,ys = size(a)
    for y in 1:ys
        for x in 1:xs
            if a.window[y,1] <= x <= a.window[y,2]
                b[x,y] = a[x,y]
            else
                b[x,y] = zero(T)
            end
        end
    end
    return b
end

function dtw(X,Y,window=defaultwindow(length(X),length(Y)),c=MySparseMatrix{Float64}((length(X),length(Y)),window))
    nX = length(X)
    nY = length(Y)
    rightlowerX = 0
    rightupperX = 0
    lowerX = 0
    upperX = 0
    xoff = 0
    m = 0.0
    cur = 0.0
    prev = Inf
    x = lowerX
    colsy = colsy2 = c.cols[1]

    @inbounds for y in 1:nY
        lowerX = window[y,1] 
        upperX = window[y,2]
        Yy = Y[y]

        if y < nY
            colsy2 = c.cols[y+1]
            rightlowerX = window[y+1,1] 
            rightupperX = window[y+1,2]
            range1 = lowerX:rightlowerX-1
            o1 = (rightlowerX > lowerX ? rightlowerX : lowerX)
            o2 = (rightupperX < upperX ? rightupperX : upperX)
            range2 = o1:o2
            range3 = rightupperX+1:upperX
        else
            range1 = lowerX:upperX
            range2 = 0:-1
            range3 = 0:-1
        end

        cur = 0.0
        prev = Inf
        for x in range1
            xoff = x-lowerX+1
            # cost of 2 cells on the left
            m = colsy[xoff]
            # prev is cost of celMySparseMatrixl above
            m = m < prev ? m : prev
            m = m == Inf ? 0.0 : m
            cur = dist(X[x],Yy) + m
            colsy[xoff] = cur
            prev = cur
        end

        for x in range2
            xoff = x-lowerX+1
            # cost of 2 cells on the left
            m = colsy[xoff]
            # prev is cost of cell above
            m = m < prev ? m : prev
            m = m == Inf ? 0.0 : m
            cur = dist(X[x],Yy) + m
            colsy[xoff] = cur
            colsy2[x-rightlowerX+1] = cur < prev ? cur : prev
            prev = cur
        end

        for x in range3
            xoff = x-lowerX+1
            # cost of 2 cells on the left
            m = colsy[xoff]
            # prev is cost of cell above
            m = m < prev ? m : prev
            m = m == Inf ? 0.0 : m
            cur = dist(X[x],Yy) + m
            colsy[xoff] = cur
            prev = cur
        end

        # update the neighbor on the right diagonal with our cost
        if upperX < rightupperX && y < nY
            colsy2[upperX-rightlowerX+1+1] = cur
        end
        colsy = colsy2
    end


    
    path = warppath(c,c.window)
    return path
end

export align

"""
Aligns vector Y using a warppath, for an example see fastdtw.
"""
function align(Y,warppath,nX=length(Y),nY=length(Y))
    cartidxes = CartesianIndices((nX,nY))
    i = cartidxes[warppath[1]][1]
    d = 0
    z = zero(Y[1])
    sum = z
    nX = nX
    res = zeros(Float64, nX)
    for w in warppath
        x,y = Tuple(cartidxes[w])
        if x == i+1
            res[i] = sum / d
            sum = z
            d = 0
            i += 1
        end
        sum += Y[y]
        d += 1
    end
    res[i] = sum / d
    return res
end

function quantize(x)
    lenx = length(x)
    minx = Float64(minimum(x))
    maxx = Float64(maximum(x))
    ret = zeros(Float64,lenx)
    
    for i in 1:lenx
        ret[i] = (x[i] - minx) / (maxx - minx)
    end
    return ret
end

function visit(x,y,dims,window)
    window[y,1] = min(window[y,1], x == 1 ? 1 : x)
    window[y,2] = max(window[y,2], x == dims[1] ? dims[1] : x+1)

    if y != dims[2]
        window[y+1,1] = min(window[y+1,1], x)
        window[y+1,2] = max(window[y+1,2], x)

        if x != dims[1]
            window[y+1,1] = min(window[y+1,1], x+1)
            window[y+1,2] = max(window[y+1,2], x+1)
        end
    end
    
end
        
function expandwindow(path, dims, newdims, radius)
    # @show newdims
    window = zeros(Int, newdims[2],2)
    window[:,1] .= typemax(Int)
    window[:,2] .= 0
    
    cartidxes = CartesianIndices(dims)
    ci = cartidxes[1]
    x1 = ci[1]
    y1 = ci[2]

    for p in 2:length(path)
        visit((x1-1)*2+1,(y1-1)*2+1,newdims,window)
        
        # x2,y2 = Tuple(cartidxes[path[p]])
        ci = cartidxes[path[p]]
        x2 = ci[1]
        y2 = ci[2]
        if x1 == x2 && y1+1 == y2
            # step right
            visit((x1-1)*2+1,(y1-1)*2+1+1,newdims,window)
        elseif x1+1 == x2 && y1 == y2
            # step down
            visit((x1-1)*2+1+1,(y1-1)*2+1,newdims,window)
        elseif x1+1 == x2 && y1+1 == y2
            # step diag
            visit((x1-1)*2+1+1,(y1-1)*2+1+1,newdims,window)
        else
            # @show dims,map(x -> ind2sub(dims,x), collect(path))
            error("invalid path, $x1, $y1, $x2, $y2")

        end
        x1 = x2
        y1 = y2
    end
    visit((x1-1)*2+1,(y1-1)*2+1,newdims,window)
    visit((x1-1)*2+1+1,(y1-1)*2+1+1,newdims,window)
    
    if (y1-1)*2 + 2 < newdims[2]
        # @assert (y1-1)*2 + 3 == newdims[2]
        visit((x1-1)*2+1,(y1-1)*2+1+1,newdims,window)
    end


    prev = window[1,1]
    if radius > 0
        for y in 1:newdims[2]
            if y > 1
                minx = window[y,1] - (window[y,1] - prev) - radius
                prev = window[y,1]
                window[y,1] = max(1, minx)
            end

            if y < newdims[2]
                maxx = window[y,2] + (window[y+1,2] - window[y,2]) + radius
                window[y,2] = min(newdims[1], maxx)
            end
        end
    end
    
    
    return window
end

function resample(X,n)
    nY = div(length(X),n)
    Y = zeros(Float64,nY)
    for x in 1:nY
        o = (x-1)*n
        Y[x] = mean(@view X[o+1:o+n])
    end
    return Y
end

export fastdtw

"""
Performs FastDTW on Y relative to X with a FastDTW radius. The larger the radius, the more FastDTW
will perform like DTW (i.e. more precise, but slower, and sucking more memory).

# Example

```
myreference = getSamples(trs,1)
radius = 90

addSamplePass(trs, x -> (path=fastdtw(myreference,x,radius); y=align(x,path); y))
```
"""
function fastdtw(X,Y,radius=0,nX=length(X),nY=length(Y))
    minTSsize = radius+4
    
    if nX < minTSsize || nY < minTSsize
        path = dtw(X,Y)
        return path
    else
        factor = 2
        shrunkX = resample(X,factor)
        shrunkY = resample(Y,factor)
        
        path = fastdtw(shrunkX,shrunkY,radius)
        
        window = expandwindow(path, (length(shrunkX),length(shrunkY)), (nX,nY), radius)
        
        path = dtw(X,Y,window)
        return path
    end
end
