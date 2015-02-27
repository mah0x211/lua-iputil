package = "iputil"
version = "scm-1"
source = {
    url = "git://github.com/mah0x211/lua-iputil.git"
}
description = {
    summary = "ip address utility",
    homepage = "https://github.com/mah0x211/lua-iputil",
    license = "MIT/X11",
    maintainer = "Masatoshi Teruya"
}
dependencies = {
    "lua >= 5.1"
}
build = {
    type = "builtin",
    modules = {
        iputil = {
            sources = { "src/iputil.c" }
        },
        ["iputil.table"] = "libs/table.lua"
    }
}
