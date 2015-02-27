local iputil = require('iputil');
local IPTable = require('iputil.table');
local tbl = IPTable.new();

-- add
local function ipadd( ip )
    local cidr = iputil.cidr( ip );
    local nhost;
    
    nhost = ifNil( tbl:add( ip ) );
    if cidr.hosts == 1 then
        ifNotEqual( nhost, cidr.hosts );
    else
        ifNotEqual( nhost, cidr.hosts + 2 );
    end
    
    ifNotTrue( tbl:contain( ip ) );
end
ipadd( '127.0.0.9/30' );
ipadd( '127.0.0.34/30' );


-- del
local function ipdel( ip )
    local cidr = iputil.cidr( ip );
    local nhost;
    
    nhost = ifNil( tbl:del( ip ) );
    if cidr.hosts == 1 then
        ifNotEqual( nhost, cidr.hosts );
    else
        ifNotEqual( nhost, cidr.hosts + 2 );
    end
    
    ifTrue( tbl:contain( ip ) );
end
ipdel( '127.0.0.9/30' );
ipdel( '127.0.0.34/30' );


-- ips iterator
local ips = {
    '127.0.0.1',
    '127.0.0.123'
};
for _, ip in ipairs( ips ) do
    ipadd( ip );
    ips[ip] = true;
end

for ip in tbl:ips() do
    ifNil( ips[ip] );
    ips[ip] = nil;
end

