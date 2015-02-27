--[[
  
  Copyright (C) 2015 Masatoshi Teruya
 
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
 
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
 
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
  
  table.lua
  lua-iputil
  Created by Masatoshi Teruya on 15/02/27.
  
--]]

-- module
local iputil = require('iputil');
local inet_ntoa = iputil.inet_ntoa;
local toCIDR = iputil.cidr;
-- constants
local BO_HOST = iputil.BO_HOST;
local BO_NET = iputil.BO_NET;
local AS_ARY = iputil.AS_ARY;
local AS_NUM = iputil.AS_NUM;
-- class
local Table = require('halo').class.Table;

function Table:init()
    local own = protected( self );
    own.iptbl = {};
    
    return self;
end


function Table:add( ip )
    local cidr, err = toCIDR( ip, AS_NUM, BO_HOST );
    local nhost;
    
    if cidr then
        local tbl = protected( self ).iptbl;
        
        nhost = cidr.to - cidr.from + 1;
        for i = cidr.from, cidr.to do
            tbl[i] = 1;
        end
    end
    
    return nhost, err;
end


function Table:del( ip )
    local cidr, err = toCIDR( ip, AS_NUM, BO_HOST );
    local nhost;
    
    if cidr then
        local tbl = protected( self ).iptbl;
        
        nhost = cidr.to - cidr.from + 1;
        for i = cidr.from, cidr.to do
            tbl[i] = nil;
        end
    end
    
    return nhost, err;
end


function Table:contain( ip )
    local cidr, err = toCIDR( ip, AS_NUM, BO_HOST );
    
    if cidr then
        local tbl = protected( self ).iptbl;
        
        for i = cidr.from, cidr.to do
            if not tbl[i] then
                return false;
            end
        end
        
        return true
    end
    
    return false, err;
end


function Table:ips()
    local tbl = protected( self ).iptbl;
    local num;
    
    return function()
        num = next( tbl, num );
        return num and inet_ntoa( num, nil, BO_HOST ) or nil;
    end
end


return Table.exports;
