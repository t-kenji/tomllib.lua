# Lua TOML package

A lightweight and tiny TOML library for Lua.

## Features

* Implemented in pure Lua: works with 5.1 or higher and LuaJIT
* Tiny: around 700sloc, 28kb
* No dependencies:

## Usage

```lua
local toml = require('tomllib')
```

### toml.encode(tbl)

```lua
local str = toml.encode({a=1, b=2, c=3, d={x='X', y='Y', z='Z'}})
```

### toml.decode(str)

```lua
local tbl = toml.decode([[
a = 1
b = 2
c = 3
d.x = 'X'
d.y = 'Y'
d.z = 'Z'
]])
```

## License

This library is free software; you can redistribute it and/or modify it under
the terms of the MIT license. See [LICENSE](LICENSE) for details.

