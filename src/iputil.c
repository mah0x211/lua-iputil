/*
 *  Copyright 2014 Masatoshi Teruya. All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 *
 *  iputil_base.c
 *  lua-iputil
 *
 *  Created by Masatoshi Teruya on 14/10/09.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <lua.h>
#include <lauxlib.h>


// helper macros for lua_State
#define lstate_fn2tbl(L,k,v) do{ \
    lua_pushstring(L,k); \
    lua_pushcfunction(L,v); \
    lua_rawset(L,-3); \
}while(0)

#define lstate_int2tbl(L,k,v) do{ \
    lua_pushstring(L,k); \
    lua_pushinteger(L,v); \
    lua_rawset(L,-3); \
}while(0)

#define lstate_str2tbl(L,k,v) do{ \
    lua_pushstring(L,k); \
    lua_pushstring(L,v); \
    lua_rawset(L,-3); \
}while(0)

#define lstate_int2arr(L,i,v) do{ \
    lua_pushnumber(L,i); \
    lua_pushnumber(L,v); \
    lua_rawset(L,-3); \
}while(0)


// xxx.xxx.xxx.xxx/xx
#define IPU_IPLEN_MAX   18

// byteorder
#define IPU_BO_NET     0
#define IPU_BO_HOST    1
// format
#define IPU_AS_STR     0
#define IPU_AS_ARY     1
#define IPU_AS_NUM     2


typedef struct {
    in_addr_t ip;
    in_addr_t mask;
    in_addr_t from;
    in_addr_t to;
    uint8_t maskbit;
} ipu_cidr_t;


static int ipstr2cidr( const char *ip, size_t len, ipu_cidr_t *cidr )
{
    if( len <= IPU_IPLEN_MAX )
    {
        struct in_addr from;
        char *ptr = NULL;
        
        // plain address
        if( !( ptr = strchr( ip, '/' ) ) )
        {
            if( inet_pton( AF_INET, ip, (void*)&from ) == 1 ){
                cidr->mask = 0xFFFFFFFFUL;
                cidr->ip = cidr->from = cidr->to = from.s_addr;
                return 0;
            }
        }
        // CIDR address
        else
        {
            char addr[len];
            
            // check ip-addr
            len = ptr - ip;
            memcpy( addr, ip, len );
            addr[len] = 0;
            if( inet_pton( AF_INET, addr, (void*)&from ) == 1 )
            {
                struct in_addr mask;
                
                ptr++;
                if( *ptr )
                {
                    char *endptr = NULL;
                    long mask = strtol( ptr, &endptr, 10 );
                    
                    if( !*endptr && mask >= 0 && mask <= 32 )
                    {
                        /*
                        11111111 11111111 11111111 11111111 << ( 32bit - mask )
                        if mask = 2
                            11111111 11111111 11111111 11111100
                        flip
                            00111111 11111111 11111111 11111111
                        */
                        cidr->maskbit = mask;
                        mask = 0xFFFFFFFFUL << ( 32 - mask );
                        mask = htonl( mask );
                        cidr->ip = from.s_addr;
                        cidr->mask = mask;
                        cidr->from = from.s_addr & mask;
                        cidr->to = cidr->from + ( mask ^ 0xFFFFFFFFUL );
                        
                        return 0;
                    }
                }
            }
        }
    }

    return -1;
}


#define setip2arr(L,k,v) do { \
    uint8_t *arr = (uint8_t*)v; \
    lua_pushliteral( L, k ); \
    lua_createtable( L, 4, 0 ); \
    lstate_int2arr( L, 1, arr[0] ); \
    lstate_int2arr( L, 2, arr[1] ); \
    lstate_int2arr( L, 3, arr[2] ); \
    lstate_int2arr( L, 4, arr[3] ); \
    lua_rawset( L, -3 ); \
}while(0)


static int cidr_lua( lua_State *L )
{
    int argc = lua_gettop( L );
    size_t len = 0;
    const char *cp = luaL_checklstring( L, 1, &len );
    ipu_cidr_t cidr;
    int bo = IPU_BO_NET;
    int as = IPU_AS_STR;
    
    // check args
    if( argc > 3 ){
        argc = 3;
    }
    switch( argc )
    {
        // byteorder
        case 3:
            if( !lua_isnil( L, 3 ) )
            {
                bo = luaL_checkint( L, 3 );
                if( bo < IPU_BO_NET || bo > IPU_BO_HOST ){
                    goto INVALID_ARGS;
                }
            }
        // format
        case 2:
            if( !lua_isnil( L, 2 ) )
            {
                as = luaL_checkint( L, 2 );
                if( as < IPU_AS_STR || as > IPU_AS_NUM ){
                    goto INVALID_ARGS;
                }
            }
    }
    
    if( ipstr2cidr( cp, len, &cidr ) == 0 )
    {
        uint32_t from = ntohl( cidr.from );
        uint32_t to = ntohl( cidr.to );
        uint32_t nip = to - from;
        struct in_addr addr = { .s_addr = cidr.from };
        char buf[IPU_IPLEN_MAX+1];
        
        snprintf( buf, IPU_IPLEN_MAX, "%s/%d", inet_ntoa( addr ), cidr.maskbit );
        buf[IPU_IPLEN_MAX] = 0;
        
        lua_newtable( L );
        lstate_str2tbl( L, "cidr", buf );
        lstate_int2tbl( L, "nip", nip > 0 ? nip + 1 : 1 );
        lstate_int2tbl( L, "byteorder", bo );
        
        // byteorder
        if( bo == IPU_BO_HOST ){
            cidr.mask = ntohl( cidr.mask );
        }
        else {
            from = cidr.from;
            to = cidr.to;
        }
        
        switch( as ){
            case IPU_AS_STR:
                addr.s_addr = cidr.mask;
                lstate_str2tbl( L, "mask", inet_ntoa( addr ) );
                addr.s_addr = from;
                lstate_str2tbl( L, "from", inet_ntoa( addr ) );
                addr.s_addr = to;
                lstate_str2tbl( L, "to", inet_ntoa( addr ) );
            break;
            case IPU_AS_ARY:
                setip2arr( L, "mask", &cidr.mask );
                setip2arr( L, "from", &from );
                setip2arr( L, "to", &to );
            break;
            case IPU_AS_NUM:
                lstate_int2tbl( L, "mask", cidr.mask );
                lstate_int2tbl( L, "from", from );
                lstate_int2tbl( L, "to", to );
            break;
        }
        return 1;
    }


INVALID_ARGS:
    // invalid format
    lua_pushnil( L );
    lua_pushstring( L, strerror( EINVAL ) );
    
    return 2;
}


static int inet_ntoa_lua( lua_State *L )
{
    int argc = lua_gettop( L );
    uint32_t net = luaL_checkinteger( L, 1 );
    int as = IPU_AS_STR;
    
    // check args
    if( argc > 3 ){
        argc = 3;
    }
    switch( argc )
    {
        // byteorder
        case 3:
            if( !lua_isnil( L, 3 ) )
            {
                int bo = luaL_checkint( L, 3 );
                if( bo < IPU_BO_NET || bo > IPU_BO_HOST ){
                    goto INVALID_ARGS;
                }
                // convert host to network byteorder
                else if( bo == IPU_BO_HOST ){
                    net = htonl( net );
                }
            }
        // format
        case 2:
            if( !lua_isnil( L, 2 ) )
            {
                as = luaL_checkint( L, 2 );
                if( as < IPU_AS_STR || as > IPU_AS_ARY ){
                    goto INVALID_ARGS;
                }
            }
    }
    
    if( as == IPU_AS_ARY ){
        uint8_t *arr = (uint8_t*)&net;
        
        lua_createtable( L, 4, 0 );
        lstate_int2arr( L, 1, arr[0] );
        lstate_int2arr( L, 2, arr[1] );
        lstate_int2arr( L, 3, arr[2] );
        lstate_int2arr( L, 4, arr[3] );
    }
    else {
        struct in_addr addr = { .s_addr = net };
        lua_pushstring( L, inet_ntoa( addr ) );
    }
    
    return 1;

INVALID_ARGS:
    // invalid format
    lua_pushnil( L );
    lua_pushstring( L, strerror( EINVAL ) );
    
    return 2;
}

static int inet_aton_lua( lua_State *L )
{
    size_t len = 0;
    const char *cp = luaL_checklstring( L, 1, &len );
    struct in_addr addr;
    
    if( inet_aton( cp, &addr ) != 0 ){
        lua_newtable( L );
        lua_pushinteger( L, addr.s_addr );
        return 1;
    }
    
    // got error
    lua_pushnil( L );
    lua_pushstring( L, strerror( EINVAL ) );
    
    return 2;
}


#define byteswap( L, convfn ) do { \
    lua_Integer val = luaL_checkinteger( L, 1 ); \
    lua_pushinteger( L, convfn( val ) ); \
}while(0)

static int htonl_lua( lua_State *L ){
    byteswap( L, htonl );
    return 1;
}

static int htons_lua( lua_State *L ){
    byteswap( L, htons );
    return 1;
}

static int ntohl_lua( lua_State *L ){
    byteswap( L, ntohl );
    return 1;
}

static int ntohs_lua( lua_State *L ){
    byteswap( L, ntohs );
    return 1;
}


LUALIB_API int luaopen_iputil( lua_State *L )
{
    struct luaL_Reg method[] = {
        { "htonl", htonl_lua },
        { "htons", htons_lua },
        { "ntohl", ntohl_lua },
        { "ntohs", ntohs_lua },
        { "inet_aton", inet_aton_lua },
        { "inet_ntoa", inet_ntoa_lua },
        { "cidr", cidr_lua },
        { NULL, NULL }
    };
    struct luaL_Reg *ptr = method;
    
    lua_newtable( L );
    do {
        lstate_fn2tbl( L, ptr->name, ptr->func );
        ptr++;
    }while( ptr->name );
    
    // add constants
    lstate_int2tbl( L, "BO_HOST", IPU_BO_HOST );
    lstate_int2tbl( L, "BO_NET", IPU_BO_NET );
    lstate_int2tbl( L, "AS_STR", IPU_AS_STR );
    lstate_int2tbl( L, "AS_ARY", IPU_AS_ARY );
    lstate_int2tbl( L, "AS_NUM", IPU_AS_NUM );
    
    return 1;
}


