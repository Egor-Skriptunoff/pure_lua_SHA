# pure_lua_SHA2

SHA2 functions written in pure Lua and optimized for speed.

---
### Installation

Just copy `sha2.lua` to Lua modules' folder.

---
### Description

This module provides functions to calculate SHA2 digest.  
This is a pure-Lua module, compatible with **Lua 5.1**, **Lua 5.2**, **Lua 5.3**, **Lua 5.4.0** (work2), **LuaJIT 2.0/2.1** and **Fengari**.

Main feature of this module: it was heavily optimized for speed.  
For every Lua version the module contains particular implementation branch to get benefits from version-specific features.

Supported hashes:
```lua
SHA-224        -- sha2.sha224()
SHA-256        -- sha2.sha256()
SHA-384        -- sha2.sha384()
SHA-512        -- sha2.sha512()
SHA-512/224    -- sha2.sha512_224()
SHA-512/256    -- sha2.sha512_256()
-- and a small bonus:
MD5            -- sha2.md5()
SHA-1          -- sha2.sha1()
HMAC           -- sha2.hmac()
```
---
### Usage

Input data should be provided as a binary string: either as a whole string or as a sequence of substrings (chunk-by-chunk loading).  
Result (SHA2 digest) is returned in hexadecimal representation (as a string of lowercase hex digits).

Simplest usage example:
```lua
local sha2 = require("sha2")
local your_hash = sha2.sha256("your string")
-- assert(your_hash == "d14d691dac70eada14d9f23ef80091bca1c75cf77cf1cd5cf2d04180ca0d9911")
```
See file "sha2_test.lua" for more examples.

---
### FAQ
---

* **Q:** Does this module calculate SHA2 really fast?
* **A:**  
Probably, this is the fastest pure Lua implementation of SHA2 you can find.  
For example, on x64 Lua 5.3 this module calculates SHA256 twice as fast as the implementation published at [lua-users.org](http://lua-users.org/wiki/SecureHashAlgorithmBw)  
This module has best performance on every Lua version because it contains several version-specific implementation branches:  
   - branch for **Lua 5.1** (emulating bitwise operators using look-up table)
   - branch for **Lua 5.2** (using **bit32** library), suitable also for **Lua 5.1** with external **bit** library
   - branch for **Lua 5.3 / 5.4** (using native **64**-bit bitwise operators)
   - branch for **Lua 5.3 / 5.4** (using native **32**-bit bitwise operators) for Lua built with `LUA_INT_TYPE=LUA_INT_INT`
   - branch for **LuaJIT without FFI library** (if you're working in a sandboxed environment with FFI disabled)
   - branch for **LuaJIT x86 without FFI library** (LuaJIT x86 has oddity because of lack of x86 CPU registers)
   - branch for **LuaJIT 2.0 with FFI library** (`bit.*` functions work only with 32-bit values)
   - branch for **LuaJIT 2.1 with FFI library** (`bit.*` functions can work with `int64_t` cdata)
  
---
* **Q:** How to get SHA2 digest as binary string instead of hexadecimal representation?
* **A:**  
Use function `sha2.hex2bin()` to convert hexadecimal to binary:
```lua
local sha2 = require("sha2")
local binary_hash = sha2.hex2bin(sha2.sha256("your string"))
-- assert(binary_hash == "\209Mi\29\172p\234\218\20\217\242>\248\0\145\188\161\199\\\247|\241\205\\\242\208A\128\202\r\153\17")
```

---
* **Q:** How to get SHA2 digest as base64 string?
* **A:**  
There are two functions (`sha2.bin2base64()` and `sha2.base642bin()`) for converting between binary and base64:
```lua
local sha2 = require("sha2")
local binary_hash = sha2.hex2bin(sha2.sha256("your string"))
local base64_hash = sha2.bin2base64(binary_hash)
-- assert(base64_hash == "0U1pHaxw6toU2fI++ACRvKHHXPd88c1c8tBBgMoNmRE=")
```

---
* **Q:** How to calculate SHA2 digest of long data stream?
* **A:**
```lua
local sha2 = require("sha2")
local append = sha2.sha256()  -- if no string is provided as argument then "append" function is returned
append("your")
append(" st")                 -- you should pass substrings to that function (chunk-by-chunk)
append("ring")
local your_hash = append()    -- and finally ask for the result
-- assert(your_hash == "d14d691dac70eada14d9f23ef80091bca1c75cf77cf1cd5cf2d04180ca0d9911")
```

---
* **Q:** How to calculate HMAC-SHA1 ?
* **A:**
```lua
local sha2 = require("sha2")
local your_hmac = sha2.hmac(sha2.sha1, "your key", "your message")
-- assert(your_hmac == "317d0dfd868a5c06c9444ac1328aa3e2bfd29fb2")
```
The same in chunk-by-chunk mode (for long messages):
```lua
local sha2 = require("sha2")
local append = sha2.hmac(sha2.sha1, "your key")
append("your")
append(" mess")
append("age")
local your_hmac = append()
-- assert(your_hmac == "317d0dfd868a5c06c9444ac1328aa3e2bfd29fb2")
```

---
### Backward-compatibility
This module will always keep backward-compatibility.  
If your program works successfully with some previous version of `sha2.lua`, it will also work with the latest version.
