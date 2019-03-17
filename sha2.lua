--------------------------------------------------------------------------------------------------------------------------
-- SHA2
--------------------------------------------------------------------------------------------------------------------------
-- MODULE: sha2
--
-- VERSION: 7 (2019-03-17)
--
-- DESCRIPTION:
--    This module contains functions to calculate SHA2 digest:
--       SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
--       and a bonus: MD5, SHA-1, HMAC
--    Written in pure Lua.
--    Compatible with:
--       Lua 5.1, Lua 5.2, Lua 5.3, Lua 5.4, Fengari, LuaJIT 2.0/2.1 (any CPU endianness).
--    Main feature of this module: it is heavily optimized for speed.
--    For every Lua version the module contains particular implementation branch to get benefits from version-specific features.
--       - branch for Lua 5.1 (emulating bitwise operators using look-up table)
--       - branch for Lua 5.2 (using bit32/bit library), suitable for both Lua 5.2 with native "bit32" and Lua 5.1 with external library "bit"
--       - branch for Lua 5.3/5.4 (using native 64-bit bitwise operators)
--       - branch for Lua 5.3/5.4 (using native 32-bit bitwise operators) for Lua built with LUA_INT_TYPE=LUA_INT_INT
--       - branch for LuaJIT without FFI library (useful in a sandboxed environment)
--       - branch for LuaJIT x86 without FFI library (LuaJIT x86 has oddity because of lack of CPU registers)
--       - branch for LuaJIT 2.0 with FFI library (bit.* functions work only with Lua numbers)
--       - branch for LuaJIT 2.1 with FFI library (bit.* functions can work with "int64_t" arguments)
--
-- USAGE:
--    Input data should be provided as a binary string: either as a whole string or as a sequence of substrings (chunk-by-chunk loading, total length < 9*10^15 bytes).
--    Result (SHA2 digest) is returned in hexadecimal representation as a string of lowercase hex digits.
--    Simplest usage example:
--       local sha2 = require("sha2")
--       local your_hash = sha2.sha256("your string")
--    See file "sha2_test.lua" for more examples.
--
-- AUTHOR: Egor (egor.skriptunoff(at)gmail.com)
-- This module is released under the MIT License (the same license as Lua itself).
--
-- CHANGELOG:
--  version     date      description
--  -------  ----------   -----------
--     7     2019-03-17   Added functions to convert to/from base64
--     6     2018-11-12   HMAC added (applicable to any hash function from this module)
--     5     2018-11-10   One more bonus added: SHA-1
--     4     2018-11-03   Bonus added: MD5
--     3     2018-11-02   Bug fixed: incorrect hashing of long (2 GByte) data streams on Lua 5.3/5.4 built with "int32" integers
--     2     2018-10-07   Decreased module loading time in Lua 5.1 implementation branch (thanks to Peter Melnichenko for giving a hint)
--     1     2018-10-06   First release
-----------------------------------------------------------------------------


local print_debug_messages = false  -- set to true to view some messages about your system's abilities and implementation branch chosen for your system

local unpack, table_concat, byte, char, string_rep, sub, gsub, gmatch, string_format, floor, ceil, tonumber =
   table.unpack or unpack, table.concat, string.byte, string.char, string.rep, string.sub, string.gsub, string.gmatch, string.format, math.floor, math.ceil, tonumber

--------------------------------------------------------------------------------
-- EXAMINING YOUR SYSTEM
--------------------------------------------------------------------------------

local function get_precision(one)
   -- "one" must be either float 1.0 or integer 1
   -- returns bits_precision, is_integer
   -- This function works correctly with all floating point datatypes (including non-IEEE-754)
   local k, n, m, prev_n = 0, one, one
   while true do
      k, prev_n, n, m = k + 1, n, n + n + 1, m + m + k % 2
      if k > 256 or n - (n - 1) ~= 1 or m - (m - 1) ~= 1 or n == m then
         return k, false   -- floating point datatype
      elseif n == prev_n then
         return k, true    -- integer datatype
      end
   end
end

-- Make sure Lua has "double" numbers
local x = 2/3
local Lua_has_double = x * 5 > 3 and x * 4 < 3 and get_precision(1.0) >= 53
assert(Lua_has_double, "at least 53-bit floating point numbers are required")

-- Q:
--    SHA2 was designed for FPU-less machines.
--    So, why floating point numbers are needed for this module?
-- A:
--    53-bit "double" numbers are useful to calculate "magic numbers" used in SHA2.
--    I prefer to write 50 LOC "magic numbers calculator" instead of storing 184 constants explicitly in this source file.

local int_prec, Lua_has_integers = get_precision(1)
local Lua_has_int64 = Lua_has_integers and int_prec == 64
local Lua_has_int32 = Lua_has_integers and int_prec == 32
assert(Lua_has_int64 or Lua_has_int32 or not Lua_has_integers, "Lua integers must be either 32-bit or 64-bit")

-- Q:
--    Does it mean that almost all non-standard configurations are not supported?
-- A:
--    Yes.  Sorry, too many problems to support all possible Lua numbers configurations.
--       Lua 5.1/5.2    with "int32"               will not work.
--       Lua 5.1/5.2    with "int64"               will not work.
--       Lua 5.1/5.2    with "int128"              will not work.
--       Lua 5.1/5.2    with "float"               will not work.
--       Lua 5.1/5.2    with "double"              is OK.          (default config for Lua 5.1, Lua 5.2, LuaJIT)
--       Lua 5.3/5.4    with "int32"  + "float"    will not work.
--       Lua 5.3/5.4    with "int64"  + "float"    will not work.
--       Lua 5.3/5.4    with "int128" + "float"    will not work.
--       Lua 5.3/5.4    with "int32"  + "double"   is OK.          (config used by Fengari)
--       Lua 5.3/5.4    with "int64"  + "double"   is OK.          (default config for Lua 5.3, Lua 5.4)
--       Lua 5.3/5.4    with "int128" + "double"   will not work.
--   Using floating point numbers better than "double" instead of "double" is OK (non-IEEE-754 floating point implementation are allowed).
--   Using "int128" instead of "int64" is not OK: "int128" would require different branch of implementation for optimized SHA512.

-- Check for LuaJIT and 32-bit bitwise libraries
local is_LuaJIT = ({false, [1] = true})[1] and (type(jit) ~= "table" or jit.version_num >= 20000)  -- LuaJIT 1.x.x is treated as vanilla Lua 5.1
local is_LuaJIT_21  -- LuaJIT 2.1+
local LuaJIT_arch
local ffi           -- LuaJIT FFI library (as a table)
local b             -- 32-bit bitwise library (as a table)
local library_name

if is_LuaJIT then
   -- Assuming "bit" library is always available on LuaJIT
   b = require"bit"
   library_name = "bit"
   -- "ffi" is intentionally disabled on some systems for safety reason
   local LuaJIT_has_FFI, result = pcall(require, "ffi")
   if LuaJIT_has_FFI then
      ffi = result
   end
   is_LuaJIT_21 = not not loadstring"b=0b0"
   LuaJIT_arch = type(jit) == "table" and jit.arch or ffi and ffi.arch or nil
else
   -- For vanilla Lua, "bit"/"bit32" libraries are searched in global namespace only.  No attempt is made to load a library if it's not loaded yet.
   if type(bit) == "table" and bit.bxor then
      b = bit
      library_name = "bit"
   elseif type(bit32) == "table" and bit32.bxor then
      b = bit32
      library_name = "bit32"
   end
end

--------------------------------------------------------------------------------
-- You can disable here some of your system's abilities (for testing purposes)
--------------------------------------------------------------------------------
-- is_LuaJIT = nil
-- is_LuaJIT_21 = nil
-- ffi = nil
-- Lua_has_int32 = nil
-- Lua_has_int64 = nil
-- b, library_name = nil
--------------------------------------------------------------------------------

if print_debug_messages then
   -- Printing list of abilities of your system
   print("Abilities:")
   print("   Lua version:               "..(is_LuaJIT and "LuaJIT "..(is_LuaJIT_21 and "2.1 " or "2.0 ")..(LuaJIT_arch or "")..(ffi and " with FFI" or " without FFI") or _VERSION))
   print("   Integer bitwise operators: "..(Lua_has_int64 and "int64" or Lua_has_int32 and "int32" or "no"))
   print("   32-bit bitwise library:    "..(library_name or "not found"))
end

-- Selecting the most suitable implementation for given set of abilities
local method, branch
if is_LuaJIT and ffi then
   method = "Using 'ffi' library of LuaJIT"
   branch = "FFI"
elseif is_LuaJIT then
   method = "Using special code for FFI-less LuaJIT"
   branch = "LJ"
elseif Lua_has_int64 then
   method = "Using native int64 bitwise operators"
   branch = "INT64"
elseif Lua_has_int32 then
   method = "Using native int32 bitwise operators"
   branch = "INT32"
elseif library_name then   -- when bitwise library is available (Lua 5.2 with native library "bit32" or Lua 5.1 with external library "bit")
   method = "Using '"..library_name.."' library"
   branch = "LIB32"
else
   method = "Emulating bitwise operators using look-up table"
   branch = "EMUL"
end

if print_debug_messages then
   -- Printing the implementation selected to be used on your system
   print("Implementation selected:")
   print("   "..method)
end

--------------------------------------------------------------------------------
-- BASIC 32-BIT BITWISE FUNCTIONS
--------------------------------------------------------------------------------

local AND, OR, XOR, SHL, SHR, ROL, ROR, NOT, NORM, HEX, XOR_BYTE
-- Only low 32 bits of function arguments matter, high bits are ignored
-- The result of all functions (except HEX) is an integer inside "correct range":
--    for "bit" library:    (-2^31)..(2^31-1)
--    for "bit32" library:        0..(2^32-1)

if branch == "FFI" or branch == "LJ" or branch == "LIB32" then

   -- Your system has 32-bit bitwise library (either "bit" or "bit32")
   AND  = b.band                -- 2 arguments
   OR   = b.bor                 -- 2 arguments
   XOR  = b.bxor                -- 2..4 arguments
   SHL  = b.lshift              -- second argument is integer 0..31
   SHR  = b.rshift              -- second argument is integer 0..31
   ROL  = b.rol or b.lrotate    -- second argument is integer 0..31
   ROR  = b.ror or b.rrotate    -- second argument is integer 0..31
   NOT  = b.bnot                -- only for LuaJIT
   NORM = b.tobit               -- only for LuaJIT
   HEX  = b.tohex               -- returns string of 8 lowercase hexadecimal digits
   assert(AND and OR and XOR and SHL and SHR and ROL and ROR and NOT, "Library '"..library_name.."' is incomplete")
   XOR_BYTE = XOR               -- XOR of two bytes (only for HMAC), inputs and output are 0..255

elseif branch == "EMUL" then

   -- Emulating 32-bit bitwise operation using 53-bit floating point arithmetic.

   function SHL(x, n)
      return (x * 2^n) % 2^32
   end

   function SHR(x, n)
      x = x % 2^32 / 2^n
      return x - x % 1
   end

   function ROL(x, n)
      x = x % 2^32 * 2^n
      local r = x % 2^32
      return r + (x - r) / 2^32
   end

   function ROR(x, n)
      x = x % 2^32 / 2^n
      local r = x % 1
      return r * 2^32 + (x - r)
   end

   local AND_of_two_bytes = {[0] = 0}  -- look-up table (256*256 entries)
   local idx = 0
   for y = 0, 127 * 256, 256 do
      for x = y, y + 127 do
         x = AND_of_two_bytes[x] * 2
         AND_of_two_bytes[idx] = x
         AND_of_two_bytes[idx + 1] = x
         AND_of_two_bytes[idx + 256] = x
         AND_of_two_bytes[idx + 257] = x + 1
         idx = idx + 2
      end
      idx = idx + 256
   end

   local function and_or_xor(x, y, operation)
      -- operation: nil = AND, 1 = OR, 2 = XOR
      local x0 = x % 2^32
      local y0 = y % 2^32
      local rx = x0 % 256
      local ry = y0 % 256
      local res = AND_of_two_bytes[rx + ry * 256]
      x = x0 - rx
      y = (y0 - ry) / 256
      rx = x % 65536
      ry = y % 256
      res = res + AND_of_two_bytes[rx + ry] * 256
      x = (x - rx) / 256
      y = (y - ry) / 256
      rx = x % 65536 + y % 256
      res = res + AND_of_two_bytes[rx] * 65536
      res = res + AND_of_two_bytes[(x + y - rx) / 256] * 16777216
      if operation then
         res = x0 + y0 - operation * res
      end
      return res
   end

   function AND(x, y)
      return and_or_xor(x, y)
   end

   function OR(x, y)
      return and_or_xor(x, y, 1)
   end

   function XOR(x, y, z, t)          -- 2..4 arguments
      if z then
         if t then
            z = and_or_xor(z, t, 2)
         end
         y = and_or_xor(y, z, 2)
      end
      return and_or_xor(x, y, 2)
   end

   function XOR_BYTE(x, y)
      return x + y - 2 * AND_of_two_bytes[x + y * 256]
   end

end

HEX = HEX or
   function (x) -- returns string of 8 lowercase hexadecimal digits
      return string_format("%08x", x % 4294967296)
   end

local function XOR32A5(x)
   return XOR(x, 0xA5A5A5A5) % 4294967296
end

--------------------------------------------------------------------------------
-- CREATING OPTIMIZED INNER LOOP
--------------------------------------------------------------------------------

-- Inner loop functions
local sha256_feed_64, sha512_feed_128, md5_feed_64, sha1_feed_64

-- Arrays of SHA2 "magic numbers" (in "INT64" and "FFI" branches "*_lo" arrays contain 64-bit values)
local sha2_K_lo, sha2_K_hi, sha2_H_lo, sha2_H_hi = {}, {}, {}, {}
local sha2_H_ext256 = {[224] = {}, [256] = sha2_H_hi}
local sha2_H_ext512_lo, sha2_H_ext512_hi = {[384] = {}, [512] = sha2_H_lo}, {[384] = {}, [512] = sha2_H_hi}
local md5_K, md5_sha1_H = {}, {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
local md5_next_shift = {0, 0, 0, 0, 0, 0, 0, 0, 28, 25, 26, 27, 0, 0, 10, 9, 11, 12, 0, 15, 16, 17, 18, 0, 20, 22, 23, 21}

local HEX64, XOR64A5   -- defined only for branches that internally use 64-bit integers: "INT64" and "FFI"
local common_W = {}    -- temporary table shared between all calculations (to avoid creating new temporary table every time)
local K_lo_modulo, hi_factor = 4294967296, 0


if branch == "FFI" then

   -- SHA256 implementation for "LuaJIT with FFI" branch

   local common_W_FFI_int32 = ffi.new"int32_t[80]"   -- 64 is enough for SHA256, but 80 is needed for SHA-1

   function sha256_feed_64(H, K, str, offs, size)
      -- offs >= 0, size >= 0, size is multiple of 64
      local W = common_W_FFI_int32
      for pos = offs, offs + size - 1, 64 do
         for j = 0, 15 do
            pos = pos + 4
            local a, b, c, d = byte(str, pos - 3, pos)   -- slow, but doesn't depend on endianness
            W[j] = OR(SHL(a, 24), SHL(b, 16), SHL(c, 8), d)
         end
         for j = 16, 63 do
            local a, b = W[j-15], W[j-2]
            W[j] = NORM( XOR(ROR(a, 7), ROL(a, 14), SHR(a, 3)) + XOR(ROL(b, 15), ROL(b, 13), SHR(b, 10)) + W[j-7] + W[j-16] )
         end
         local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
         for j = 0, 63, 8 do  -- Thanks to Peter Cawley for this workaround (unroll the loop to avoid "PHI shuffling too complex" due to PHIs overlap)
            local z = NORM( XOR(g, AND(e, XOR(f, g))) + XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + (W[j] + K[j+1] + h) )
            h, g, f, e = g, f, e, NORM( d + z )
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
            z = NORM( XOR(g, AND(e, XOR(f, g))) + XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + (W[j+1] + K[j+2] + h) )
            h, g, f, e = g, f, e, NORM( d + z )
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
            z = NORM( XOR(g, AND(e, XOR(f, g))) + XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + (W[j+2] + K[j+3] + h) )
            h, g, f, e = g, f, e, NORM( d + z )
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
            z = NORM( XOR(g, AND(e, XOR(f, g))) + XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + (W[j+3] + K[j+4] + h) )
            h, g, f, e = g, f, e, NORM( d + z )
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
            z = NORM( XOR(g, AND(e, XOR(f, g))) + XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + (W[j+4] + K[j+5] + h) )
            h, g, f, e = g, f, e, NORM( d + z )
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
            z = NORM( XOR(g, AND(e, XOR(f, g))) + XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + (W[j+5] + K[j+6] + h) )
            h, g, f, e = g, f, e, NORM( d + z )
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
            z = NORM( XOR(g, AND(e, XOR(f, g))) + XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + (W[j+6] + K[j+7] + h) )
            h, g, f, e = g, f, e, NORM( d + z )
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
            z = NORM( XOR(g, AND(e, XOR(f, g))) + XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + (W[j+7] + K[j+8] + h) )
            h, g, f, e = g, f, e, NORM( d + z )
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
         end
         H[1], H[2], H[3], H[4] = NORM(a + H[1]), NORM(b + H[2]), NORM(c + H[3]), NORM(d + H[4])
         H[5], H[6], H[7], H[8] = NORM(e + H[5]), NORM(f + H[6]), NORM(g + H[7]), NORM(h + H[8])
      end
   end

   local common_W_FFI_int64 = ffi.new"int64_t[80]"
   local int64 = ffi.typeof"int64_t"
   local int32 = ffi.typeof"int32_t"
   local uint32 = ffi.typeof"uint32_t"

   hi_factor = int64(2^32)

   if is_LuaJIT_21 then

      -- implementation of SHA512 for "LuaJIT 2.1 + FFI" branch

      local AND64, OR64, XOR64, SHL64, SHR64, ROL64, ROR64  -- introducing synonyms for better readability
          = AND,   OR,   XOR,   SHL,   SHR,   ROL,   ROR
      HEX64 = HEX

      local A5_long = 0xA5A5A5A5 * int64(2^32 + 1)  -- I can't use constant 0xA5A5A5A5A5A5A5A5LL because it will raise syntax error on other Lua versions

      function XOR64A5(long)
         return XOR64(long, A5_long)
      end

      function sha512_feed_128(H, _, K, _, str, offs, size)
         -- offs >= 0, size >= 0, size is multiple of 128
         local W = common_W_FFI_int64
         for pos = offs, offs + size - 1, 128 do
            for j = 0, 15 do
               pos = pos + 8
               local a, b, c, d, e, f, g, h = byte(str, pos - 7, pos)   -- slow, but doesn't depend on endianness
               W[j] = OR64(OR(SHL(a, 24), SHL(b, 16), SHL(c, 8), d) * int64(2^32), uint32(int32(OR(SHL(e, 24), SHL(f, 16), SHL(g, 8), h))))
            end
            for j = 16, 79 do
               local a, b = W[j-15], W[j-2]
               W[j] = XOR64(ROR64(a, 1), ROR64(a, 8), SHR64(a, 7)) + XOR64(ROR64(b, 19), ROL64(b, 3), SHR64(b, 6)) + W[j-7] + W[j-16]
            end
            local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
            for j = 0, 79, 8 do
               local z = XOR64(ROR64(e, 14), ROR64(e, 18), ROL64(e, 23)) + XOR64(g, AND64(e, XOR64(f, g))) + h + K[j+1] + W[j]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XOR64(AND64(XOR64(a, b), c), AND64(a, b)) + XOR64(ROR64(a, 28), ROL64(a, 25), ROL64(a, 30)) + z
               z = XOR64(ROR64(e, 14), ROR64(e, 18), ROL64(e, 23)) + XOR64(g, AND64(e, XOR64(f, g))) + h + K[j+2] + W[j+1]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XOR64(AND64(XOR64(a, b), c), AND64(a, b)) + XOR64(ROR64(a, 28), ROL64(a, 25), ROL64(a, 30)) + z
               z = XOR64(ROR64(e, 14), ROR64(e, 18), ROL64(e, 23)) + XOR64(g, AND64(e, XOR64(f, g))) + h + K[j+3] + W[j+2]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XOR64(AND64(XOR64(a, b), c), AND64(a, b)) + XOR64(ROR64(a, 28), ROL64(a, 25), ROL64(a, 30)) + z
               z = XOR64(ROR64(e, 14), ROR64(e, 18), ROL64(e, 23)) + XOR64(g, AND64(e, XOR64(f, g))) + h + K[j+4] + W[j+3]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XOR64(AND64(XOR64(a, b), c), AND64(a, b)) + XOR64(ROR64(a, 28), ROL64(a, 25), ROL64(a, 30)) + z
               z = XOR64(ROR64(e, 14), ROR64(e, 18), ROL64(e, 23)) + XOR64(g, AND64(e, XOR64(f, g))) + h + K[j+5] + W[j+4]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XOR64(AND64(XOR64(a, b), c), AND64(a, b)) + XOR64(ROR64(a, 28), ROL64(a, 25), ROL64(a, 30)) + z
               z = XOR64(ROR64(e, 14), ROR64(e, 18), ROL64(e, 23)) + XOR64(g, AND64(e, XOR64(f, g))) + h + K[j+6] + W[j+5]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XOR64(AND64(XOR64(a, b), c), AND64(a, b)) + XOR64(ROR64(a, 28), ROL64(a, 25), ROL64(a, 30)) + z
               z = XOR64(ROR64(e, 14), ROR64(e, 18), ROL64(e, 23)) + XOR64(g, AND64(e, XOR64(f, g))) + h + K[j+7] + W[j+6]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XOR64(AND64(XOR64(a, b), c), AND64(a, b)) + XOR64(ROR64(a, 28), ROL64(a, 25), ROL64(a, 30)) + z
               z = XOR64(ROR64(e, 14), ROR64(e, 18), ROL64(e, 23)) + XOR64(g, AND64(e, XOR64(f, g))) + h + K[j+8] + W[j+7]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XOR64(AND64(XOR64(a, b), c), AND64(a, b)) + XOR64(ROR64(a, 28), ROL64(a, 25), ROL64(a, 30)) + z
            end
            H[1] = a + H[1]
            H[2] = b + H[2]
            H[3] = c + H[3]
            H[4] = d + H[4]
            H[5] = e + H[5]
            H[6] = f + H[6]
            H[7] = g + H[7]
            H[8] = h + H[8]
         end
      end

   else  -- LuaJIT 2.0

      -- implementation of SHA512 for "LuaJIT 2.0 + FFI" branch

      local union64 = ffi.typeof"union{int64_t i64; struct{int32_t lo, hi;} i32;}"
      do  -- make sure the struct is endianness-compatible
         local u = union64(1)
         if u.i32.lo < u.i32.hi then
            union64 = ffi.typeof"union{int64_t i64; struct{int32_t hi, lo;} i32;}"
         end
      end
      local unions64 = ffi.typeof("$[?]", union64)
      local U = unions64(3)   -- this array of unions is used for fast splitting int64 into int32_high and int32_low

      -- "xorrific" 64-bit functions :-)
      -- int64 input is splitted into two int32 parts, some bitwise 32-bit operations are performed, finally the result is converted to int64
      -- these functions are needed because bit.* functions in LuaJIT 2.0 don't work with int64_t arguments

      local function XORROR64_1(a)
         -- return XOR64(ROR64(a, 1), ROR64(a, 8), SHR64(a, 7))
         U[0].i64 = a
         local a_lo, a_hi = U[0].i32.lo, U[0].i32.hi
         local t_lo = XOR(OR(SHR(a_lo, 1), SHL(a_hi, 31)), OR(SHR(a_lo, 8), SHL(a_hi, 24)), OR(SHR(a_lo, 7), SHL(a_hi, 25)))
         local t_hi = XOR(OR(SHR(a_hi, 1), SHL(a_lo, 31)), OR(SHR(a_hi, 8), SHL(a_lo, 24)), SHR(a_hi, 7))
         return t_hi * int64(2^32) + uint32(int32(t_lo))
      end

      local function XORROR64_2(b)
         -- return XOR64(ROR64(b, 19), ROL64(b, 3), SHR64(b, 6))
         U[0].i64 = b
         local b_lo, b_hi = U[0].i32.lo, U[0].i32.hi
         local u_lo = XOR(OR(SHR(b_lo, 19), SHL(b_hi, 13)), OR(SHL(b_lo, 3), SHR(b_hi, 29)), OR(SHR(b_lo, 6), SHL(b_hi, 26)))
         local u_hi = XOR(OR(SHR(b_hi, 19), SHL(b_lo, 13)), OR(SHL(b_hi, 3), SHR(b_lo, 29)), SHR(b_hi, 6))
         return u_hi * int64(2^32) + uint32(int32(u_lo))
      end

      local function XORROR64_3(e)
         -- return XOR64(ROR64(e, 14), ROR64(e, 18), ROL64(e, 23))
         U[0].i64 = e
         local e_lo, e_hi = U[0].i32.lo, U[0].i32.hi
         local u_lo = XOR(OR(SHR(e_lo, 14), SHL(e_hi, 18)), OR(SHR(e_lo, 18), SHL(e_hi, 14)), OR(SHL(e_lo, 23), SHR(e_hi, 9)))
         local u_hi = XOR(OR(SHR(e_hi, 14), SHL(e_lo, 18)), OR(SHR(e_hi, 18), SHL(e_lo, 14)), OR(SHL(e_hi, 23), SHR(e_lo, 9)))
         return u_hi * int64(2^32) + uint32(int32(u_lo))
      end

      local function XORROR64_6(a)
         -- return XOR64(ROR64(a, 28), ROL64(a, 25), ROL64(a, 30))
         U[0].i64 = a
         local b_lo, b_hi = U[0].i32.lo, U[0].i32.hi
         local u_lo = XOR(OR(SHR(b_lo, 28), SHL(b_hi, 4)), OR(SHL(b_lo, 30), SHR(b_hi, 2)), OR(SHL(b_lo, 25), SHR(b_hi, 7)))
         local u_hi = XOR(OR(SHR(b_hi, 28), SHL(b_lo, 4)), OR(SHL(b_hi, 30), SHR(b_lo, 2)), OR(SHL(b_hi, 25), SHR(b_lo, 7)))
         return u_hi * int64(2^32) + uint32(int32(u_lo))
      end

      local function XORROR64_4(e, f, g)
         -- return XOR64(g, AND64(e, XOR64(f, g)))
         U[0].i64 = f
         U[1].i64 = g
         U[2].i64 = e
         local f_lo, f_hi = U[0].i32.lo, U[0].i32.hi
         local g_lo, g_hi = U[1].i32.lo, U[1].i32.hi
         local e_lo, e_hi = U[2].i32.lo, U[2].i32.hi
         local result_lo = XOR(g_lo, AND(e_lo, XOR(f_lo, g_lo)))
         local result_hi = XOR(g_hi, AND(e_hi, XOR(f_hi, g_hi)))
         return result_hi * int64(2^32) + uint32(int32(result_lo))
      end

      local function XORROR64_5(a, b, c)
         -- return XOR64(AND64(XOR64(a, b), c), AND64(a, b))
         U[0].i64 = a
         U[1].i64 = b
         U[2].i64 = c
         local a_lo, a_hi = U[0].i32.lo, U[0].i32.hi
         local b_lo, b_hi = U[1].i32.lo, U[1].i32.hi
         local c_lo, c_hi = U[2].i32.lo, U[2].i32.hi
         local result_lo = XOR(AND(XOR(a_lo, b_lo), c_lo), AND(a_lo, b_lo))
         local result_hi = XOR(AND(XOR(a_hi, b_hi), c_hi), AND(a_hi, b_hi))
         return result_hi * int64(2^32) + uint32(int32(result_lo))
      end

      function XOR64A5(long)
         -- return XOR64(long, 0xA5A5A5A5A5A5A5A5)
         U[0].i64 = long
         local lo32, hi32 = U[0].i32.lo, U[0].i32.hi
         lo32 = XOR(lo32, 0xA5A5A5A5)
         hi32 = XOR(hi32, 0xA5A5A5A5)
         return hi32 * int64(2^32) + uint32(int32(lo32))
      end

      function HEX64(long)
         U[0].i64 = long
         return HEX(U[0].i32.hi)..HEX(U[0].i32.lo)
      end

      function sha512_feed_128(H, _, K, _, str, offs, size)
         -- offs >= 0, size >= 0, size is multiple of 128
         local W = common_W_FFI_int64
         for pos = offs, offs + size - 1, 128 do
            for j = 0, 15 do
               pos = pos + 8
               local a, b, c, d, e, f, g, h = byte(str, pos - 7, pos)   -- slow, but doesn't depend on endianness
               W[j] = OR(SHL(a, 24), SHL(b, 16), SHL(c, 8), d) * int64(2^32) + uint32(int32(OR(SHL(e, 24), SHL(f, 16), SHL(g, 8), h)))
            end
            for j = 16, 79 do
               W[j] = XORROR64_1(W[j-15]) + XORROR64_2(W[j-2]) + W[j-7] + W[j-16]
            end
            local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
            for j = 0, 79, 8 do
               local z = XORROR64_3(e) + XORROR64_4(e, f, g) + h + K[j+1] + W[j]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XORROR64_5(a, b, c) + XORROR64_6(a) + z
               z = XORROR64_3(e) + XORROR64_4(e, f, g) + h + K[j+2] + W[j+1]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XORROR64_5(a, b, c) + XORROR64_6(a) + z
               z = XORROR64_3(e) + XORROR64_4(e, f, g) + h + K[j+3] + W[j+2]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XORROR64_5(a, b, c) + XORROR64_6(a) + z
               z = XORROR64_3(e) + XORROR64_4(e, f, g) + h + K[j+4] + W[j+3]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XORROR64_5(a, b, c) + XORROR64_6(a) + z
               z = XORROR64_3(e) + XORROR64_4(e, f, g) + h + K[j+5] + W[j+4]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XORROR64_5(a, b, c) + XORROR64_6(a) + z
               z = XORROR64_3(e) + XORROR64_4(e, f, g) + h + K[j+6] + W[j+5]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XORROR64_5(a, b, c) + XORROR64_6(a) + z
               z = XORROR64_3(e) + XORROR64_4(e, f, g) + h + K[j+7] + W[j+6]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XORROR64_5(a, b, c) + XORROR64_6(a) + z
               z = XORROR64_3(e) + XORROR64_4(e, f, g) + h + K[j+8] + W[j+7]
               h, g, f, e = g, f, e, z + d
               d, c, b, a = c, b, a, XORROR64_5(a, b, c) + XORROR64_6(a) + z
            end
            H[1] = a + H[1]
            H[2] = b + H[2]
            H[3] = c + H[3]
            H[4] = d + H[4]
            H[5] = e + H[5]
            H[6] = f + H[6]
            H[7] = g + H[7]
            H[8] = h + H[8]
         end
      end

   end

   -- MD5 implementation for "LuaJIT with FFI" branch

   function md5_feed_64(H, K, str, offs, size)
      -- offs >= 0, size >= 0, size is multiple of 64
      local W = common_W_FFI_int32
      for pos = offs, offs + size - 1, 64 do
         for j = 0, 15 do
            pos = pos + 4
            local a, b, c, d = byte(str, pos - 3, pos)   -- slow, but doesn't depend on endianness
            W[j] = OR(SHL(d, 24), SHL(c, 16), SHL(b, 8), a)
         end
         local a, b, c, d = H[1], H[2], H[3], H[4]
         for j = 0, 15, 4 do
            a, d, c, b = d, c, b, NORM(ROL(XOR(d, AND(b, XOR(c, d))) + (K[j+1] + W[j  ] + a),  7) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(d, AND(b, XOR(c, d))) + (K[j+2] + W[j+1] + a), 12) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(d, AND(b, XOR(c, d))) + (K[j+3] + W[j+2] + a), 17) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(d, AND(b, XOR(c, d))) + (K[j+4] + W[j+3] + a), 22) + b)
         end
         for j = 16, 31, 4 do
            local g = 5*j
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, AND(d, XOR(b, c))) + (K[j+1] + W[AND(g + 1, 15)] + a),  5) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, AND(d, XOR(b, c))) + (K[j+2] + W[AND(g + 6, 15)] + a),  9) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, AND(d, XOR(b, c))) + (K[j+3] + W[AND(g - 5, 15)] + a), 14) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, AND(d, XOR(b, c))) + (K[j+4] + W[AND(g    , 15)] + a), 20) + b)
         end
         for j = 32, 47, 4 do
            local g = 3*j
            a, d, c, b = d, c, b, NORM(ROL(XOR(b, c, d) + (K[j+1] + W[AND(g + 5, 15)] + a),  4) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(b, c, d) + (K[j+2] + W[AND(g + 8, 15)] + a), 11) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(b, c, d) + (K[j+3] + W[AND(g - 5, 15)] + a), 16) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(b, c, d) + (K[j+4] + W[AND(g - 2, 15)] + a), 23) + b)
         end
         for j = 48, 63, 4 do
            local g = 7*j
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, OR(b, NOT(d))) + (K[j+1] + W[AND(g    , 15)] + a),  6) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, OR(b, NOT(d))) + (K[j+2] + W[AND(g + 7, 15)] + a), 10) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, OR(b, NOT(d))) + (K[j+3] + W[AND(g - 2, 15)] + a), 15) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, OR(b, NOT(d))) + (K[j+4] + W[AND(g + 5, 15)] + a), 21) + b)
         end
         H[1], H[2], H[3], H[4] = NORM(a + H[1]), NORM(b + H[2]), NORM(c + H[3]), NORM(d + H[4])
      end
   end

   -- SHA-1 implementation for "LuaJIT with FFI" branch

   function sha1_feed_64(H, str, offs, size)
      -- offs >= 0, size >= 0, size is multiple of 64
      local W = common_W_FFI_int32
      for pos = offs, offs + size - 1, 64 do
         for j = 0, 15 do
            pos = pos + 4
            local a, b, c, d = byte(str, pos - 3, pos)   -- slow, but doesn't depend on endianness
            W[j] = OR(SHL(a, 24), SHL(b, 16), SHL(c, 8), d)
         end
         for j = 16, 79 do
            W[j] = ROL(XOR(W[j-3], W[j-8], W[j-14], W[j-16]), 1)
         end
         local a, b, c, d, e = H[1], H[2], H[3], H[4], H[5]
         for j = 0, 19, 5 do
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(d, AND(b, XOR(d, c))) + (W[j]   + 0x5A827999 + e))          -- constant = floor(2^30 * sqrt(2))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(d, AND(b, XOR(d, c))) + (W[j+1] + 0x5A827999 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(d, AND(b, XOR(d, c))) + (W[j+2] + 0x5A827999 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(d, AND(b, XOR(d, c))) + (W[j+3] + 0x5A827999 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(d, AND(b, XOR(d, c))) + (W[j+4] + 0x5A827999 + e))
         end
         for j = 20, 39, 5 do
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j]   + 0x6ED9EBA1 + e))                       -- 2^30 * sqrt(3)
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+1] + 0x6ED9EBA1 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+2] + 0x6ED9EBA1 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+3] + 0x6ED9EBA1 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+4] + 0x6ED9EBA1 + e))
         end
         for j = 40, 59, 5 do
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(AND(d, XOR(b, c)), AND(b, c)) + (W[j]   + 0x8F1BBCDC + e))  -- 2^30 * sqrt(5)
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(AND(d, XOR(b, c)), AND(b, c)) + (W[j+1] + 0x8F1BBCDC + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(AND(d, XOR(b, c)), AND(b, c)) + (W[j+2] + 0x8F1BBCDC + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(AND(d, XOR(b, c)), AND(b, c)) + (W[j+3] + 0x8F1BBCDC + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(AND(d, XOR(b, c)), AND(b, c)) + (W[j+4] + 0x8F1BBCDC + e))
         end
         for j = 60, 79, 5 do
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j]   + 0xCA62C1D6 + e))                       -- 2^30 * sqrt(10)
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+1] + 0xCA62C1D6 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+2] + 0xCA62C1D6 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+3] + 0xCA62C1D6 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+4] + 0xCA62C1D6 + e))
         end
         H[1], H[2], H[3], H[4], H[5] = NORM(a + H[1]), NORM(b + H[2]), NORM(c + H[3]), NORM(d + H[4]), NORM(e + H[5])
      end
   end

end


if branch == "LJ" then

   -- SHA256 implementation for "LuaJIT without FFI" branch

   function sha256_feed_64(H, K, str, offs, size)
      -- offs >= 0, size >= 0, size is multiple of 64
      local W = common_W
      for pos = offs, offs + size - 1, 64 do
         for j = 1, 16 do
            pos = pos + 4
            local a, b, c, d = byte(str, pos - 3, pos)
            W[j] = OR(SHL(a, 24), SHL(b, 16), SHL(c, 8), d)
         end
         for j = 17, 64 do
            local a, b = W[j-15], W[j-2]
            W[j] = NORM( NORM( XOR(ROR(a, 7), ROL(a, 14), SHR(a, 3)) + XOR(ROL(b, 15), ROL(b, 13), SHR(b, 10)) ) + NORM( W[j-7] + W[j-16] ) )
         end
         local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
         for j = 1, 64, 8 do  -- Thanks to Peter Cawley for this workaround (unroll the loop to avoid "PHI shuffling too complex" due to PHIs overlap)
            local z = NORM( XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + XOR(g, AND(e, XOR(f, g))) + (K[j] + W[j] + h) )
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
            z = NORM( XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + XOR(g, AND(e, XOR(f, g))) + (K[j+1] + W[j+1] + h) )
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
            z = NORM( XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + XOR(g, AND(e, XOR(f, g))) + (K[j+2] + W[j+2] + h) )
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
            z = NORM( XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + XOR(g, AND(e, XOR(f, g))) + (K[j+3] + W[j+3] + h) )
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
            z = NORM( XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + XOR(g, AND(e, XOR(f, g))) + (K[j+4] + W[j+4] + h) )
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
            z = NORM( XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + XOR(g, AND(e, XOR(f, g))) + (K[j+5] + W[j+5] + h) )
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
            z = NORM( XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + XOR(g, AND(e, XOR(f, g))) + (K[j+6] + W[j+6] + h) )
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
            z = NORM( XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + XOR(g, AND(e, XOR(f, g))) + (K[j+7] + W[j+7] + h) )
            h, g, f, e = g, f, e, NORM(d + z)
            d, c, b, a = c, b, a, NORM( XOR(AND(a, XOR(b, c)), AND(b, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10)) + z )
         end
         H[1], H[2], H[3], H[4] = NORM(a + H[1]), NORM(b + H[2]), NORM(c + H[3]), NORM(d + H[4])
         H[5], H[6], H[7], H[8] = NORM(e + H[5]), NORM(f + H[6]), NORM(g + H[7]), NORM(h + H[8])
      end
   end

   local function ADD64_4(a_lo, a_hi, b_lo, b_hi, c_lo, c_hi, d_lo, d_hi)
      local sum_lo = a_lo % 2^32 + b_lo % 2^32 + c_lo % 2^32 + d_lo % 2^32
      local sum_hi = a_hi + b_hi + c_hi + d_hi
      local result_lo = NORM( sum_lo )
      local result_hi = NORM( sum_hi + floor(sum_lo / 2^32) )
      return result_lo, result_hi
   end

   if LuaJIT_arch == "x86" then  -- Special trick is required to avoid "PHI shuffling too complex" on x86 platform

      -- implementation of SHA512 for "LuaJIT x86 without FFI" branch

      function sha512_feed_128(H_lo, H_hi, K_lo, K_hi, str, offs, size)
         -- offs >= 0, size >= 0, size is multiple of 128
         -- W1_hi, W1_lo, W2_hi, W2_lo, ...   Wk_hi = W[2*k-1], Wk_lo = W[2*k]
         local W = common_W
         for pos = offs, offs + size - 1, 128 do
            for j = 1, 16*2 do
               pos = pos + 4
               local a, b, c, d = byte(str, pos - 3, pos)
               W[j] = OR(SHL(a, 24), SHL(b, 16), SHL(c, 8), d)
            end
            for jj = 17*2, 80*2, 2 do
               local a_lo, a_hi = W[jj-30], W[jj-31]
               local t_lo = XOR(OR(SHR(a_lo, 1), SHL(a_hi, 31)), OR(SHR(a_lo, 8), SHL(a_hi, 24)), OR(SHR(a_lo, 7), SHL(a_hi, 25)))
               local t_hi = XOR(OR(SHR(a_hi, 1), SHL(a_lo, 31)), OR(SHR(a_hi, 8), SHL(a_lo, 24)), SHR(a_hi, 7))
               local b_lo, b_hi = W[jj-4], W[jj-5]
               local u_lo = XOR(OR(SHR(b_lo, 19), SHL(b_hi, 13)), OR(SHL(b_lo, 3), SHR(b_hi, 29)), OR(SHR(b_lo, 6), SHL(b_hi, 26)))
               local u_hi = XOR(OR(SHR(b_hi, 19), SHL(b_lo, 13)), OR(SHL(b_hi, 3), SHR(b_lo, 29)), SHR(b_hi, 6))
               W[jj], W[jj-1] = ADD64_4(t_lo, t_hi, u_lo, u_hi, W[jj-14], W[jj-15], W[jj-32], W[jj-33])
            end
            local a_lo, b_lo, c_lo, d_lo, e_lo, f_lo, g_lo, h_lo = H_lo[1], H_lo[2], H_lo[3], H_lo[4], H_lo[5], H_lo[6], H_lo[7], H_lo[8]
            local a_hi, b_hi, c_hi, d_hi, e_hi, f_hi, g_hi, h_hi = H_hi[1], H_hi[2], H_hi[3], H_hi[4], H_hi[5], H_hi[6], H_hi[7], H_hi[8]
            local zero = 0
            for j = 1, 80 do
               local t_lo = XOR(g_lo, AND(e_lo, XOR(f_lo, g_lo)))
               local t_hi = XOR(g_hi, AND(e_hi, XOR(f_hi, g_hi)))
               local u_lo = XOR(OR(SHR(e_lo, 14), SHL(e_hi, 18)), OR(SHR(e_lo, 18), SHL(e_hi, 14)), OR(SHL(e_lo, 23), SHR(e_hi, 9)))
               local u_hi = XOR(OR(SHR(e_hi, 14), SHL(e_lo, 18)), OR(SHR(e_hi, 18), SHL(e_lo, 14)), OR(SHL(e_hi, 23), SHR(e_lo, 9)))
               local sum_lo = u_lo % 2^32 + t_lo % 2^32 + h_lo % 2^32 + K_lo[j] + W[2*j] % 2^32
               local z_lo, z_hi = NORM( sum_lo ), NORM( u_hi + t_hi + h_hi + K_hi[j] + W[2*j-1] + floor(sum_lo / 2^32) )
               zero = zero + zero  -- this thick is needed to avoid "PHI shuffling too complex" due to PHIs overlap
               h_lo, h_hi, g_lo, g_hi, f_lo, f_hi = OR(zero, g_lo), OR(zero, g_hi), OR(zero, f_lo), OR(zero, f_hi), OR(zero, e_lo), OR(zero, e_hi)
               local sum_lo = z_lo % 2^32 + d_lo % 2^32
               e_lo, e_hi = NORM( sum_lo ), NORM( z_hi + d_hi + floor(sum_lo / 2^32) )
               d_lo, d_hi, c_lo, c_hi, b_lo, b_hi = OR(zero, c_lo), OR(zero, c_hi), OR(zero, b_lo), OR(zero, b_hi), OR(zero, a_lo), OR(zero, a_hi)
               u_lo = XOR(OR(SHR(b_lo, 28), SHL(b_hi, 4)), OR(SHL(b_lo, 30), SHR(b_hi, 2)), OR(SHL(b_lo, 25), SHR(b_hi, 7)))
               u_hi = XOR(OR(SHR(b_hi, 28), SHL(b_lo, 4)), OR(SHL(b_hi, 30), SHR(b_lo, 2)), OR(SHL(b_hi, 25), SHR(b_lo, 7)))
               t_lo = OR(AND(d_lo, c_lo), AND(b_lo, XOR(d_lo, c_lo)))
               t_hi = OR(AND(d_hi, c_hi), AND(b_hi, XOR(d_hi, c_hi)))
               local sum_lo = z_lo % 2^32 + t_lo % 2^32 + u_lo % 2^32
               a_lo, a_hi = NORM( sum_lo ), NORM( z_hi + t_hi + u_hi + floor(sum_lo / 2^32) )
            end
            H_lo[1], H_hi[1] = ADD64_4(H_lo[1], H_hi[1], a_lo, a_hi, 0, 0, 0, 0)
            H_lo[2], H_hi[2] = ADD64_4(H_lo[2], H_hi[2], b_lo, b_hi, 0, 0, 0, 0)
            H_lo[3], H_hi[3] = ADD64_4(H_lo[3], H_hi[3], c_lo, c_hi, 0, 0, 0, 0)
            H_lo[4], H_hi[4] = ADD64_4(H_lo[4], H_hi[4], d_lo, d_hi, 0, 0, 0, 0)
            H_lo[5], H_hi[5] = ADD64_4(H_lo[5], H_hi[5], e_lo, e_hi, 0, 0, 0, 0)
            H_lo[6], H_hi[6] = ADD64_4(H_lo[6], H_hi[6], f_lo, f_hi, 0, 0, 0, 0)
            H_lo[7], H_hi[7] = ADD64_4(H_lo[7], H_hi[7], g_lo, g_hi, 0, 0, 0, 0)
            H_lo[8], H_hi[8] = ADD64_4(H_lo[8], H_hi[8], h_lo, h_hi, 0, 0, 0, 0)
         end
      end

   else  -- all platforms except x86

      -- implementation of SHA512 for "LuaJIT non-x86 without FFI" branch

      function sha512_feed_128(H_lo, H_hi, K_lo, K_hi, str, offs, size)
         -- offs >= 0, size >= 0, size is multiple of 128
         -- W1_hi, W1_lo, W2_hi, W2_lo, ...   Wk_hi = W[2*k-1], Wk_lo = W[2*k]
         local W = common_W
         for pos = offs, offs + size - 1, 128 do
            for j = 1, 16*2 do
               pos = pos + 4
               local a, b, c, d = byte(str, pos - 3, pos)
               W[j] = OR(SHL(a, 24), SHL(b, 16), SHL(c, 8), d)
            end
            for jj = 17*2, 80*2, 2 do
               local a_lo, a_hi = W[jj-30], W[jj-31]
               local t_lo = XOR(OR(SHR(a_lo, 1), SHL(a_hi, 31)), OR(SHR(a_lo, 8), SHL(a_hi, 24)), OR(SHR(a_lo, 7), SHL(a_hi, 25)))
               local t_hi = XOR(OR(SHR(a_hi, 1), SHL(a_lo, 31)), OR(SHR(a_hi, 8), SHL(a_lo, 24)), SHR(a_hi, 7))
               local b_lo, b_hi = W[jj-4], W[jj-5]
               local u_lo = XOR(OR(SHR(b_lo, 19), SHL(b_hi, 13)), OR(SHL(b_lo, 3), SHR(b_hi, 29)), OR(SHR(b_lo, 6), SHL(b_hi, 26)))
               local u_hi = XOR(OR(SHR(b_hi, 19), SHL(b_lo, 13)), OR(SHL(b_hi, 3), SHR(b_lo, 29)), SHR(b_hi, 6))
               W[jj], W[jj-1] = ADD64_4(t_lo, t_hi, u_lo, u_hi, W[jj-14], W[jj-15], W[jj-32], W[jj-33])
            end
            local a_lo, b_lo, c_lo, d_lo, e_lo, f_lo, g_lo, h_lo = H_lo[1], H_lo[2], H_lo[3], H_lo[4], H_lo[5], H_lo[6], H_lo[7], H_lo[8]
            local a_hi, b_hi, c_hi, d_hi, e_hi, f_hi, g_hi, h_hi = H_hi[1], H_hi[2], H_hi[3], H_hi[4], H_hi[5], H_hi[6], H_hi[7], H_hi[8]
            for j = 1, 80 do
               local t_lo = XOR(g_lo, AND(e_lo, XOR(f_lo, g_lo)))
               local t_hi = XOR(g_hi, AND(e_hi, XOR(f_hi, g_hi)))
               local u_lo = XOR(OR(SHR(e_lo, 14), SHL(e_hi, 18)), OR(SHR(e_lo, 18), SHL(e_hi, 14)), OR(SHL(e_lo, 23), SHR(e_hi, 9)))
               local u_hi = XOR(OR(SHR(e_hi, 14), SHL(e_lo, 18)), OR(SHR(e_hi, 18), SHL(e_lo, 14)), OR(SHL(e_hi, 23), SHR(e_lo, 9)))
               local sum_lo = u_lo % 2^32 + t_lo % 2^32 + h_lo % 2^32 + K_lo[j] + W[2*j] % 2^32
               local z_lo, z_hi = NORM( sum_lo ), NORM( u_hi + t_hi + h_hi + K_hi[j] + W[2*j-1] + floor(sum_lo / 2^32) )
               h_lo, h_hi, g_lo, g_hi, f_lo, f_hi = g_lo, g_hi, f_lo, f_hi, e_lo, e_hi
               local sum_lo = z_lo % 2^32 + d_lo % 2^32
               e_lo, e_hi = NORM( sum_lo ), NORM( z_hi + d_hi + floor(sum_lo / 2^32) )
               d_lo, d_hi, c_lo, c_hi, b_lo, b_hi = c_lo, c_hi, b_lo, b_hi, a_lo, a_hi
               u_lo = XOR(OR(SHR(b_lo, 28), SHL(b_hi, 4)), OR(SHL(b_lo, 30), SHR(b_hi, 2)), OR(SHL(b_lo, 25), SHR(b_hi, 7)))
               u_hi = XOR(OR(SHR(b_hi, 28), SHL(b_lo, 4)), OR(SHL(b_hi, 30), SHR(b_lo, 2)), OR(SHL(b_hi, 25), SHR(b_lo, 7)))
               t_lo = OR(AND(d_lo, c_lo), AND(b_lo, XOR(d_lo, c_lo)))
               t_hi = OR(AND(d_hi, c_hi), AND(b_hi, XOR(d_hi, c_hi)))
               local sum_lo = z_lo % 2^32 + u_lo % 2^32 + t_lo % 2^32
               a_lo, a_hi = NORM( sum_lo ), NORM( z_hi + u_hi + t_hi + floor(sum_lo / 2^32) )
            end
            H_lo[1], H_hi[1] = ADD64_4(H_lo[1], H_hi[1], a_lo, a_hi, 0, 0, 0, 0)
            H_lo[2], H_hi[2] = ADD64_4(H_lo[2], H_hi[2], b_lo, b_hi, 0, 0, 0, 0)
            H_lo[3], H_hi[3] = ADD64_4(H_lo[3], H_hi[3], c_lo, c_hi, 0, 0, 0, 0)
            H_lo[4], H_hi[4] = ADD64_4(H_lo[4], H_hi[4], d_lo, d_hi, 0, 0, 0, 0)
            H_lo[5], H_hi[5] = ADD64_4(H_lo[5], H_hi[5], e_lo, e_hi, 0, 0, 0, 0)
            H_lo[6], H_hi[6] = ADD64_4(H_lo[6], H_hi[6], f_lo, f_hi, 0, 0, 0, 0)
            H_lo[7], H_hi[7] = ADD64_4(H_lo[7], H_hi[7], g_lo, g_hi, 0, 0, 0, 0)
            H_lo[8], H_hi[8] = ADD64_4(H_lo[8], H_hi[8], h_lo, h_hi, 0, 0, 0, 0)
         end
      end

   end

   -- MD5 implementation for "LuaJIT without FFI" branch

   function md5_feed_64(H, K, str, offs, size)
      -- offs >= 0, size >= 0, size is multiple of 64
      local W = common_W
      for pos = offs, offs + size - 1, 64 do
         for j = 1, 16 do
            pos = pos + 4
            local a, b, c, d = byte(str, pos - 3, pos)
            W[j] = OR(SHL(d, 24), SHL(c, 16), SHL(b, 8), a)
         end
         local a, b, c, d = H[1], H[2], H[3], H[4]
         for j = 1, 16, 4 do
            a, d, c, b = d, c, b, NORM(ROL(XOR(d, AND(b, XOR(c, d))) + (K[j  ] + W[j  ] + a),  7) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(d, AND(b, XOR(c, d))) + (K[j+1] + W[j+1] + a), 12) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(d, AND(b, XOR(c, d))) + (K[j+2] + W[j+2] + a), 17) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(d, AND(b, XOR(c, d))) + (K[j+3] + W[j+3] + a), 22) + b)
         end
         for j = 17, 32, 4 do
            local g = 5*j-4
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, AND(d, XOR(b, c))) + (K[j  ] + W[AND(g     , 15) + 1] + a),  5) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, AND(d, XOR(b, c))) + (K[j+1] + W[AND(g +  5, 15) + 1] + a),  9) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, AND(d, XOR(b, c))) + (K[j+2] + W[AND(g + 10, 15) + 1] + a), 14) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, AND(d, XOR(b, c))) + (K[j+3] + W[AND(g -  1, 15) + 1] + a), 20) + b)
         end
         for j = 33, 48, 4 do
            local g = 3*j+2
            a, d, c, b = d, c, b, NORM(ROL(XOR(b, c, d) + (K[j  ] + W[AND(g    , 15) + 1] + a),  4) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(b, c, d) + (K[j+1] + W[AND(g + 3, 15) + 1] + a), 11) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(b, c, d) + (K[j+2] + W[AND(g + 6, 15) + 1] + a), 16) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(b, c, d) + (K[j+3] + W[AND(g - 7, 15) + 1] + a), 23) + b)
         end
         for j = 49, 64, 4 do
            local g = j*7
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, OR(b, NOT(d))) + (K[j  ] + W[AND(g - 7, 15) + 1] + a),  6) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, OR(b, NOT(d))) + (K[j+1] + W[AND(g    , 15) + 1] + a), 10) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, OR(b, NOT(d))) + (K[j+2] + W[AND(g + 7, 15) + 1] + a), 15) + b)
            a, d, c, b = d, c, b, NORM(ROL(XOR(c, OR(b, NOT(d))) + (K[j+3] + W[AND(g - 2, 15) + 1] + a), 21) + b)
         end
         H[1], H[2], H[3], H[4] = NORM(a + H[1]), NORM(b + H[2]), NORM(c + H[3]), NORM(d + H[4])
      end
   end

   -- SHA-1 implementation for "LuaJIT without FFI" branch

   function sha1_feed_64(H, str, offs, size)
      -- offs >= 0, size >= 0, size is multiple of 64
      local W = common_W
      for pos = offs, offs + size - 1, 64 do
         for j = 1, 16 do
            pos = pos + 4
            local a, b, c, d = byte(str, pos - 3, pos)
            W[j] = OR(SHL(a, 24), SHL(b, 16), SHL(c, 8), d)
         end
         for j = 17, 80 do
            W[j] = ROL(XOR(W[j-3], W[j-8], W[j-14], W[j-16]), 1)
         end
         local a, b, c, d, e = H[1], H[2], H[3], H[4], H[5]
         for j = 1, 20, 5 do
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(d, AND(b, XOR(d, c))) + (W[j]   + 0x5A827999 + e))          -- constant = floor(2^30 * sqrt(2))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(d, AND(b, XOR(d, c))) + (W[j+1] + 0x5A827999 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(d, AND(b, XOR(d, c))) + (W[j+2] + 0x5A827999 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(d, AND(b, XOR(d, c))) + (W[j+3] + 0x5A827999 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(d, AND(b, XOR(d, c))) + (W[j+4] + 0x5A827999 + e))
         end
         for j = 21, 40, 5 do
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j]   + 0x6ED9EBA1 + e))                       -- 2^30 * sqrt(3)
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+1] + 0x6ED9EBA1 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+2] + 0x6ED9EBA1 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+3] + 0x6ED9EBA1 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+4] + 0x6ED9EBA1 + e))
         end
         for j = 41, 60, 5 do
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(AND(d, XOR(b, c)), AND(b, c)) + (W[j]   + 0x8F1BBCDC + e))  -- 2^30 * sqrt(5)
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(AND(d, XOR(b, c)), AND(b, c)) + (W[j+1] + 0x8F1BBCDC + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(AND(d, XOR(b, c)), AND(b, c)) + (W[j+2] + 0x8F1BBCDC + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(AND(d, XOR(b, c)), AND(b, c)) + (W[j+3] + 0x8F1BBCDC + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(AND(d, XOR(b, c)), AND(b, c)) + (W[j+4] + 0x8F1BBCDC + e))
         end
         for j = 61, 80, 5 do
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j]   + 0xCA62C1D6 + e))                       -- 2^30 * sqrt(10)
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+1] + 0xCA62C1D6 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+2] + 0xCA62C1D6 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+3] + 0xCA62C1D6 + e))
            e, d, c, b, a = d, c, ROR(b, 2), a, NORM(ROL(a, 5) + XOR(b, c, d) + (W[j+4] + 0xCA62C1D6 + e))
         end
         H[1], H[2], H[3], H[4], H[5] = NORM(a + H[1]), NORM(b + H[2]), NORM(c + H[3]), NORM(d + H[4]), NORM(e + H[5])
      end
   end

end


if branch == "INT64" then

   -- implementation for Lua 5.3/5.4

   hi_factor = 4294967296

   HEX64, XOR64A5, XOR_BYTE, sha256_feed_64, sha512_feed_128, md5_feed_64, sha1_feed_64 = load[[
      local md5_next_shift = ...
      local string_format, string_unpack = string.format, string.unpack

      local function HEX64(x)
         return string_format("%016x", x)
      end

      local function XOR64A5(x)
         return x ~ 0xa5a5a5a5a5a5a5a5
      end

      local function XOR_BYTE(x, y)
         return x ~ y
      end

      local common_W = {}

      local function sha256_feed_64(H, K, str, offs, size)
         -- offs >= 0, size >= 0, size is multiple of 64
         local W = common_W
         local h1, h2, h3, h4, h5, h6, h7, h8 = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
         for pos = offs + 1, offs + size, 64 do
            W[1], W[2], W[3], W[4], W[5], W[6], W[7], W[8], W[9], W[10], W[11], W[12], W[13], W[14], W[15], W[16] =
               string_unpack(">I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4", str, pos)
            for j = 17, 64 do
               local a = W[j-15]
               a = a<<32 | a
               local b = W[j-2]
               b = b<<32 | b
               W[j] = (a>>7 ~ a>>18 ~ a>>35) + (b>>17 ~ b>>19 ~ b>>42) + W[j-7] + W[j-16] & (1<<32)-1
            end
            local a, b, c, d, e, f, g, h = h1, h2, h3, h4, h5, h6, h7, h8
            for j = 1, 64 do
               e = e<<32 | e & (1<<32)-1
               local z = (e>>6 ~ e>>11 ~ e>>25) + (g ~ e & (f ~ g)) + h + K[j] + W[j]
               h = g
               g = f
               f = e
               e = z + d
               d = c
               c = b
               b = a
               a = a<<32 | a & (1<<32)-1
               a = z + ((a ~ c) & d ~ a & c) + (a>>2 ~ a>>13 ~ a>>22)
            end
            h1 = a + h1
            h2 = b + h2
            h3 = c + h3
            h4 = d + h4
            h5 = e + h5
            h6 = f + h6
            h7 = g + h7
            h8 = h + h8
         end
         H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8] = h1, h2, h3, h4, h5, h6, h7, h8
      end

      local function sha512_feed_128(H, _, K, _, str, offs, size)
         -- offs >= 0, size >= 0, size is multiple of 128
         local W = common_W
         local h1, h2, h3, h4, h5, h6, h7, h8 = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
         for pos = offs + 1, offs + size, 128 do
            W[1], W[2], W[3], W[4], W[5], W[6], W[7], W[8], W[9], W[10], W[11], W[12], W[13], W[14], W[15], W[16] =
               string_unpack(">i8i8i8i8i8i8i8i8i8i8i8i8i8i8i8i8", str, pos)
            for j = 17, 80 do
               local a = W[j-15]
               local b = W[j-2]
               W[j] = (a >> 1 ~ a >> 7 ~ a >> 8 ~ a << 56 ~ a << 63) + (b >> 6 ~ b >> 19 ~ b >> 61 ~ b << 3 ~ b << 45) + W[j-7] + W[j-16]
            end
            local a, b, c, d, e, f, g, h = h1, h2, h3, h4, h5, h6, h7, h8
            for j = 1, 80 do
               local z = (e >> 14 ~ e >> 18 ~ e >> 41 ~ e << 23 ~ e << 46 ~ e << 50) + (g ~ e & (f ~ g)) + h + K[j] + W[j]
               h = g
               g = f
               f = e
               e = z + d
               d = c
               c = b
               b = a
               a = z + ((a ~ c) & d ~ a & c) + (a >> 28 ~ a >> 34 ~ a >> 39 ~ a << 25 ~ a << 30 ~ a << 36)
            end
            h1 = a + h1
            h2 = b + h2
            h3 = c + h3
            h4 = d + h4
            h5 = e + h5
            h6 = f + h6
            h7 = g + h7
            h8 = h + h8
         end
         H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8] = h1, h2, h3, h4, h5, h6, h7, h8
      end

      local function md5_feed_64(H, K, str, offs, size)
         -- offs >= 0, size >= 0, size is multiple of 64
         local W, md5_next_shift = common_W, md5_next_shift
         local h1, h2, h3, h4 = H[1], H[2], H[3], H[4]
         for pos = offs + 1, offs + size, 64 do
            W[1], W[2], W[3], W[4], W[5], W[6], W[7], W[8], W[9], W[10], W[11], W[12], W[13], W[14], W[15], W[16] =
               string_unpack("<I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4", str, pos)
            local a, b, c, d = h1, h2, h3, h4
            local s = 32-7
            for j = 1, 16 do
               local F = (d ~ b & (c ~ d)) + a + K[j] + W[j]
               a = d
               d = c
               c = b
               b = ((F<<32 | F & (1<<32)-1) >> s) + b
               s = md5_next_shift[s]
            end
            s = 32-5
            for j = 17, 32 do
               local F = (c ~ d & (b ~ c)) + a + K[j] + W[(5*j-4 & 15) + 1]
               a = d
               d = c
               c = b
               b = ((F<<32 | F & (1<<32)-1) >> s) + b
               s = md5_next_shift[s]
            end
            s = 32-4
            for j = 33, 48 do
               local F = (b ~ c ~ d) + a + K[j] + W[(3*j+2 & 15) + 1]
               a = d
               d = c
               c = b
               b = ((F<<32 | F & (1<<32)-1) >> s) + b
               s = md5_next_shift[s]
            end
            s = 32-6
            for j = 49, 64 do
               local F = (c ~ (b | ~d)) + a + K[j] + W[(j*7-7 & 15) + 1]
               a = d
               d = c
               c = b
               b = ((F<<32 | F & (1<<32)-1) >> s) + b
               s = md5_next_shift[s]
            end
            h1 = a + h1
            h2 = b + h2
            h3 = c + h3
            h4 = d + h4
         end
         H[1], H[2], H[3], H[4] = h1, h2, h3, h4
      end

      local function sha1_feed_64(H, str, offs, size)
         -- offs >= 0, size >= 0, size is multiple of 64
         local W = common_W
         local h1, h2, h3, h4, h5 = H[1], H[2], H[3], H[4], H[5]
         for pos = offs + 1, offs + size, 64 do
            W[1], W[2], W[3], W[4], W[5], W[6], W[7], W[8], W[9], W[10], W[11], W[12], W[13], W[14], W[15], W[16] =
               string_unpack(">I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4I4", str, pos)
            for j = 17, 80 do
               local a = W[j-3] ~ W[j-8] ~ W[j-14] ~ W[j-16]
               W[j] = (a<<32 | a) << 1 >> 32
            end
            local a, b, c, d, e = h1, h2, h3, h4, h5
            for j = 1, 20 do
               local z = ((a<<32 | a & (1<<32)-1) >> 27) + (d ~ b & (c ~ d)) + 0x5A827999 + W[j] + e      -- constant = floor(2^30 * sqrt(2))
               e = d
               d = c
               c = (b<<32 | b & (1<<32)-1) >> 2
               b = a
               a = z
            end
            for j = 21, 40 do
               local z = ((a<<32 | a & (1<<32)-1) >> 27) + (b ~ c ~ d) + 0x6ED9EBA1 + W[j] + e            -- 2^30 * sqrt(3)
               e = d
               d = c
               c = (b<<32 | b & (1<<32)-1) >> 2
               b = a
               a = z
            end
            for j = 41, 60 do
               local z = ((a<<32 | a & (1<<32)-1) >> 27) + ((b ~ c) & d ~ b & c) + 0x8F1BBCDC + W[j] + e  -- 2^30 * sqrt(5)
               e = d
               d = c
               c = (b<<32 | b & (1<<32)-1) >> 2
               b = a
               a = z
            end
            for j = 61, 80 do
               local z = ((a<<32 | a & (1<<32)-1) >> 27) + (b ~ c ~ d) + 0xCA62C1D6 + W[j] + e            -- 2^30 * sqrt(10)
               e = d
               d = c
               c = (b<<32 | b & (1<<32)-1) >> 2
               b = a
               a = z
            end
            h1 = a + h1
            h2 = b + h2
            h3 = c + h3
            h4 = d + h4
            h5 = e + h5
         end
         H[1], H[2], H[3], H[4], H[5] = h1, h2, h3, h4, h5
      end

      return HEX64, XOR64A5, XOR_BYTE, sha256_feed_64, sha512_feed_128, md5_feed_64, sha1_feed_64
   ]](md5_next_shift)

end


if branch == "INT32" then

   -- implementation for Lua 5.3/5.4 having non-standard numbers config "int32"+"double" (built with LUA_INT_TYPE=LUA_INT_INT)

   K_lo_modulo = 2^32

   function HEX(x) -- returns string of 8 lowercase hexadecimal digits
      return string_format("%08x", x)
   end

   XOR32A5, XOR_BYTE, sha256_feed_64, sha512_feed_128, md5_feed_64, sha1_feed_64 = load[[
      local md5_next_shift = ...
      local string_unpack, floor = string.unpack, math.floor

      local function XOR32A5(x)
         return x ~ 0xA5A5A5A5
      end

      local function XOR_BYTE(x, y)
         return x ~ y
      end

      local common_W = {}

      local function sha256_feed_64(H, K, str, offs, size)
         -- offs >= 0, size >= 0, size is multiple of 64
         local W = common_W
         local h1, h2, h3, h4, h5, h6, h7, h8 = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
         for pos = offs + 1, offs + size, 64 do
            W[1], W[2], W[3], W[4], W[5], W[6], W[7], W[8], W[9], W[10], W[11], W[12], W[13], W[14], W[15], W[16] =
               string_unpack(">i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4", str, pos)
            for j = 17, 64 do
               local a, b = W[j-15], W[j-2]
               W[j] = (a>>7 ~ a<<25 ~ a<<14 ~ a>>18 ~ a>>3) + (b<<15 ~ b>>17 ~ b<<13 ~ b>>19 ~ b>>10) + W[j-7] + W[j-16]
            end
            local a, b, c, d, e, f, g, h = h1, h2, h3, h4, h5, h6, h7, h8
            for j = 1, 64 do
               local z = (e>>6 ~ e<<26 ~ e>>11 ~ e<<21 ~ e>>25 ~ e<<7) + (g ~ e & (f ~ g)) + h + K[j] + W[j]
               h = g
               g = f
               f = e
               e = z + d
               d = c
               c = b
               b = a
               a = z + ((a ~ c) & d ~ a & c) + (a>>2 ~ a<<30 ~ a>>13 ~ a<<19 ~ a<<10 ~ a>>22)
            end
            h1 = a + h1
            h2 = b + h2
            h3 = c + h3
            h4 = d + h4
            h5 = e + h5
            h6 = f + h6
            h7 = g + h7
            h8 = h + h8
         end
         H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8] = h1, h2, h3, h4, h5, h6, h7, h8
      end

      local function sha512_feed_128(H_lo, H_hi, K_lo, K_hi, str, offs, size)
         -- offs >= 0, size >= 0, size is multiple of 128
         -- W1_hi, W1_lo, W2_hi, W2_lo, ...   Wk_hi = W[2*k-1], Wk_lo = W[2*k]
         local floor, W = floor, common_W
         local h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo = H_lo[1], H_lo[2], H_lo[3], H_lo[4], H_lo[5], H_lo[6], H_lo[7], H_lo[8]
         local h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi = H_hi[1], H_hi[2], H_hi[3], H_hi[4], H_hi[5], H_hi[6], H_hi[7], H_hi[8]
         for pos = offs + 1, offs + size, 128 do
            W[1], W[2], W[3], W[4], W[5], W[6], W[7], W[8], W[9], W[10], W[11], W[12], W[13], W[14], W[15], W[16],
               W[17], W[18], W[19], W[20], W[21], W[22], W[23], W[24], W[25], W[26], W[27], W[28], W[29], W[30], W[31], W[32] =
               string_unpack(">i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4", str, pos)
            for jj = 17*2, 80*2, 2 do
               local a_lo, a_hi, b_lo, b_hi = W[jj-30], W[jj-31], W[jj-4], W[jj-5]
               local tmp =
                  (a_lo>>1 ~ a_hi<<31 ~ a_lo>>8 ~ a_hi<<24 ~ a_lo>>7 ~ a_hi<<25) % 2^32
                  + (b_lo>>19 ~ b_hi<<13 ~ b_lo<<3 ~ b_hi>>29 ~ b_lo>>6 ~ b_hi<<26) % 2^32
                  + W[jj-14] % 2^32 + W[jj-32] % 2^32
               W[jj-1] =
                  (a_hi>>1 ~ a_lo<<31 ~ a_hi>>8 ~ a_lo<<24 ~ a_hi>>7)
                  + (b_hi>>19 ~ b_lo<<13 ~ b_hi<<3 ~ b_lo>>29 ~ b_hi>>6)
                  + W[jj-15] + W[jj-33] + floor(tmp / 2^32)
               W[jj] = 0|((tmp + 2^31) % 2^32 - 2^31)
            end
            local a_lo, b_lo, c_lo, d_lo, e_lo, f_lo, g_lo, h_lo = h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo
            local a_hi, b_hi, c_hi, d_hi, e_hi, f_hi, g_hi, h_hi = h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi
            for j = 1, 80 do
               local jj = 2*j
               local z_lo = (e_lo>>14 ~ e_hi<<18 ~ e_lo>>18 ~ e_hi<<14 ~ e_lo<<23 ~ e_hi>>9) % 2^32 + (g_lo ~ e_lo & (f_lo ~ g_lo)) % 2^32 + h_lo % 2^32 + K_lo[j] + W[jj] % 2^32
               local z_hi = (e_hi>>14 ~ e_lo<<18 ~ e_hi>>18 ~ e_lo<<14 ~ e_hi<<23 ~ e_lo>>9) + (g_hi ~ e_hi & (f_hi ~ g_hi)) + h_hi + K_hi[j] + W[jj-1] + floor(z_lo / 2^32)
               z_lo = z_lo % 2^32
               h_lo = g_lo
               h_hi = g_hi
               g_lo = f_lo
               g_hi = f_hi
               f_lo = e_lo
               f_hi = e_hi
               e_lo = z_lo + d_lo % 2^32
               e_hi = z_hi + d_hi + floor(e_lo / 2^32)
               e_lo = 0|((e_lo + 2^31) % 2^32 - 2^31)
               d_lo = c_lo
               d_hi = c_hi
               c_lo = b_lo
               c_hi = b_hi
               b_lo = a_lo
               b_hi = a_hi
               z_lo = z_lo + (d_lo & c_lo ~ b_lo & (d_lo ~ c_lo)) % 2^32 + (b_lo>>28 ~ b_hi<<4 ~ b_lo<<30 ~ b_hi>>2 ~ b_lo<<25 ~ b_hi>>7) % 2^32
               a_hi = z_hi + (d_hi & c_hi ~ b_hi & (d_hi ~ c_hi)) + (b_hi>>28 ~ b_lo<<4 ~ b_hi<<30 ~ b_lo>>2 ~ b_hi<<25 ~ b_lo>>7) + floor(z_lo / 2^32)
               a_lo = 0|((z_lo + 2^31) % 2^32 - 2^31)
            end
            a_lo = h1_lo % 2^32 + a_lo % 2^32
            h1_hi = h1_hi + a_hi + floor(a_lo / 2^32)
            h1_lo = 0|((a_lo + 2^31) % 2^32 - 2^31)
            a_lo = h2_lo % 2^32 + b_lo % 2^32
            h2_hi = h2_hi + b_hi + floor(a_lo / 2^32)
            h2_lo = 0|((a_lo + 2^31) % 2^32 - 2^31)
            a_lo = h3_lo % 2^32 + c_lo % 2^32
            h3_hi = h3_hi + c_hi + floor(a_lo / 2^32)
            h3_lo = 0|((a_lo + 2^31) % 2^32 - 2^31)
            a_lo = h4_lo % 2^32 + d_lo % 2^32
            h4_hi = h4_hi + d_hi + floor(a_lo / 2^32)
            h4_lo = 0|((a_lo + 2^31) % 2^32 - 2^31)
            a_lo = h5_lo % 2^32 + e_lo % 2^32
            h5_hi = h5_hi + e_hi + floor(a_lo / 2^32)
            h5_lo = 0|((a_lo + 2^31) % 2^32 - 2^31)
            a_lo = h6_lo % 2^32 + f_lo % 2^32
            h6_hi = h6_hi + f_hi + floor(a_lo / 2^32)
            h6_lo = 0|((a_lo + 2^31) % 2^32 - 2^31)
            a_lo = h7_lo % 2^32 + g_lo % 2^32
            h7_hi = h7_hi + g_hi + floor(a_lo / 2^32)
            h7_lo = 0|((a_lo + 2^31) % 2^32 - 2^31)
            a_lo = h8_lo % 2^32 + h_lo % 2^32
            h8_hi = h8_hi + h_hi + floor(a_lo / 2^32)
            h8_lo = 0|((a_lo + 2^31) % 2^32 - 2^31)
         end
         H_lo[1], H_lo[2], H_lo[3], H_lo[4], H_lo[5], H_lo[6], H_lo[7], H_lo[8] = h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo
         H_hi[1], H_hi[2], H_hi[3], H_hi[4], H_hi[5], H_hi[6], H_hi[7], H_hi[8] = h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi
      end

      local function md5_feed_64(H, K, str, offs, size)
         -- offs >= 0, size >= 0, size is multiple of 64
         local W, md5_next_shift = common_W, md5_next_shift
         local h1, h2, h3, h4 = H[1], H[2], H[3], H[4]
         for pos = offs + 1, offs + size, 64 do
            W[1], W[2], W[3], W[4], W[5], W[6], W[7], W[8], W[9], W[10], W[11], W[12], W[13], W[14], W[15], W[16] =
               string_unpack("<i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4", str, pos)
            local a, b, c, d = h1, h2, h3, h4
            local s = 32-7
            for j = 1, 16 do
               local F = (d ~ b & (c ~ d)) + a + K[j] + W[j]
               a = d
               d = c
               c = b
               b = (F << 32-s | F>>s) + b
               s = md5_next_shift[s]
            end
            s = 32-5
            for j = 17, 32 do
               local F = (c ~ d & (b ~ c)) + a + K[j] + W[(5*j-4 & 15) + 1]
               a = d
               d = c
               c = b
               b = (F << 32-s | F>>s) + b
               s = md5_next_shift[s]
            end
            s = 32-4
            for j = 33, 48 do
               local F = (b ~ c ~ d) + a + K[j] + W[(3*j+2 & 15) + 1]
               a = d
               d = c
               c = b
               b = (F << 32-s | F>>s) + b
               s = md5_next_shift[s]
            end
            s = 32-6
            for j = 49, 64 do
               local F = (c ~ (b | ~d)) + a + K[j] + W[(j*7-7 & 15) + 1]
               a = d
               d = c
               c = b
               b = (F << 32-s | F>>s) + b
               s = md5_next_shift[s]
            end
            h1 = a + h1
            h2 = b + h2
            h3 = c + h3
            h4 = d + h4
         end
         H[1], H[2], H[3], H[4] = h1, h2, h3, h4
      end

      local function sha1_feed_64(H, str, offs, size)
         -- offs >= 0, size >= 0, size is multiple of 64
         local W = common_W
         local h1, h2, h3, h4, h5 = H[1], H[2], H[3], H[4], H[5]
         for pos = offs + 1, offs + size, 64 do
            W[1], W[2], W[3], W[4], W[5], W[6], W[7], W[8], W[9], W[10], W[11], W[12], W[13], W[14], W[15], W[16] =
               string_unpack(">i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4i4", str, pos)
            for j = 17, 80 do
               local a = W[j-3] ~ W[j-8] ~ W[j-14] ~ W[j-16]
               W[j] = a << 1 ~ a >> 31
            end
            local a, b, c, d, e = h1, h2, h3, h4, h5
            for j = 1, 20 do
               local z = (a << 5 ~ a >> 27) + (d ~ b & (c ~ d)) + 0x5A827999 + W[j] + e      -- constant = floor(2^30 * sqrt(2))
               e = d
               d = c
               c = b << 30 ~ b >> 2
               b = a
               a = z
            end
            for j = 21, 40 do
               local z = (a << 5 ~ a >> 27) + (b ~ c ~ d) + 0x6ED9EBA1 + W[j] + e            -- 2^30 * sqrt(3)
               e = d
               d = c
               c = b << 30 ~ b >> 2
               b = a
               a = z
            end
            for j = 41, 60 do
               local z = (a << 5 ~ a >> 27) + ((b ~ c) & d ~ b & c) + 0x8F1BBCDC + W[j] + e  -- 2^30 * sqrt(5)
               e = d
               d = c
               c = b << 30 ~ b >> 2
               b = a
               a = z
            end
            for j = 61, 80 do
               local z = (a << 5 ~ a >> 27) + (b ~ c ~ d) + 0xCA62C1D6 + W[j] + e            -- 2^30 * sqrt(10)
               e = d
               d = c
               c = b << 30 ~ b >> 2
               b = a
               a = z
            end
            h1 = a + h1
            h2 = b + h2
            h3 = c + h3
            h4 = d + h4
            h5 = e + h5
         end
         H[1], H[2], H[3], H[4], H[5] = h1, h2, h3, h4, h5
      end

      return XOR32A5, XOR_BYTE, sha256_feed_64, sha512_feed_128, md5_feed_64, sha1_feed_64
   ]](md5_next_shift)

end


if branch == "LIB32" or branch == "EMUL" then

   -- implementation for Lua 5.1/5.2 (with or without bitwise library available)

   function sha256_feed_64(H, K, str, offs, size)
      -- offs >= 0, size >= 0, size is multiple of 64
      local W = common_W
      local h1, h2, h3, h4, h5, h6, h7, h8 = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
      for pos = offs, offs + size - 1, 64 do
         for j = 1, 16 do
            pos = pos + 4
            local a, b, c, d = byte(str, pos - 3, pos)
            W[j] = ((a * 256 + b) * 256 + c) * 256 + d
         end
         for j = 17, 64 do
            local a, b = W[j-15], W[j-2]
            W[j] = XOR(ROR(a, 7), ROL(a, 14), SHR(a, 3)) + XOR(ROL(b, 15), ROL(b, 13), SHR(b, 10)) + W[j-7] + W[j-16]
         end
         local a, b, c, d, e, f, g, h = h1, h2, h3, h4, h5, h6, h7, h8
         for j = 1, 64 do
            local z = XOR(ROR(e, 6), ROR(e, 11), ROL(e, 7)) + AND(e, f) + AND(-1-e, g) + h + K[j] + W[j]
            h = g
            g = f
            f = e
            e = z + d
            d = c
            c = b
            b = a
            a = z + AND(d, c) + AND(a, XOR(d, c)) + XOR(ROR(a, 2), ROR(a, 13), ROL(a, 10))
         end
         h1, h2, h3, h4 = (a + h1) % 4294967296, (b + h2) % 4294967296, (c + h3) % 4294967296, (d + h4) % 4294967296
         h5, h6, h7, h8 = (e + h5) % 4294967296, (f + h6) % 4294967296, (g + h7) % 4294967296, (h + h8) % 4294967296
      end
      H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8] = h1, h2, h3, h4, h5, h6, h7, h8
   end

   function sha512_feed_128(H_lo, H_hi, K_lo, K_hi, str, offs, size)
      -- offs >= 0, size >= 0, size is multiple of 128
      -- W1_hi, W1_lo, W2_hi, W2_lo, ...   Wk_hi = W[2*k-1], Wk_lo = W[2*k]
      local W = common_W
      local h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo = H_lo[1], H_lo[2], H_lo[3], H_lo[4], H_lo[5], H_lo[6], H_lo[7], H_lo[8]
      local h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi = H_hi[1], H_hi[2], H_hi[3], H_hi[4], H_hi[5], H_hi[6], H_hi[7], H_hi[8]
      for pos = offs, offs + size - 1, 128 do
         for j = 1, 16*2 do
            pos = pos + 4
            local a, b, c, d = byte(str, pos - 3, pos)
            W[j] = ((a * 256 + b) * 256 + c) * 256 + d
         end
         for jj = 17*2, 80*2, 2 do
            local a_lo, a_hi, b_lo, b_hi = W[jj-30], W[jj-31], W[jj-4], W[jj-5]
            local tmp1 = XOR(SHR(a_lo, 1) + SHL(a_hi, 31), SHR(a_lo, 8) + SHL(a_hi, 24), SHR(a_lo, 7) + SHL(a_hi, 25)) % 4294967296 + XOR(SHR(b_lo, 19) + SHL(b_hi, 13), SHL(b_lo, 3) + SHR(b_hi, 29), SHR(b_lo, 6) + SHL(b_hi, 26)) % 4294967296 + W[jj-14] + W[jj-32]
            local tmp2 = tmp1 % 4294967296
            W[jj-1] = XOR(SHR(a_hi, 1) + SHL(a_lo, 31), SHR(a_hi, 8) + SHL(a_lo, 24), SHR(a_hi, 7)) + XOR(SHR(b_hi, 19) + SHL(b_lo, 13), SHL(b_hi, 3) + SHR(b_lo, 29), SHR(b_hi, 6)) + W[jj-15] + W[jj-33] + (tmp1 - tmp2) / 4294967296
            W[jj] = tmp2
         end
         local a_lo, b_lo, c_lo, d_lo, e_lo, f_lo, g_lo, h_lo = h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo
         local a_hi, b_hi, c_hi, d_hi, e_hi, f_hi, g_hi, h_hi = h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi
         for j = 1, 80 do
            local jj = 2*j
            local tmp1 = XOR(SHR(e_lo, 14) + SHL(e_hi, 18), SHR(e_lo, 18) + SHL(e_hi, 14), SHL(e_lo, 23) + SHR(e_hi, 9)) % 4294967296 + (AND(e_lo, f_lo) + AND(-1-e_lo, g_lo)) % 4294967296 + h_lo + K_lo[j] + W[jj]
            local z_lo = tmp1 % 4294967296
            local z_hi = XOR(SHR(e_hi, 14) + SHL(e_lo, 18), SHR(e_hi, 18) + SHL(e_lo, 14), SHL(e_hi, 23) + SHR(e_lo, 9)) + AND(e_hi, f_hi) + AND(-1-e_hi, g_hi) + h_hi + K_hi[j] + W[jj-1] + (tmp1 - z_lo) / 4294967296
            h_lo = g_lo
            h_hi = g_hi
            g_lo = f_lo
            g_hi = f_hi
            f_lo = e_lo
            f_hi = e_hi
            tmp1 = z_lo + d_lo
            e_lo = tmp1 % 4294967296
            e_hi = z_hi + d_hi + (tmp1 - e_lo) / 4294967296
            d_lo = c_lo
            d_hi = c_hi
            c_lo = b_lo
            c_hi = b_hi
            b_lo = a_lo
            b_hi = a_hi
            tmp1 = z_lo + (AND(d_lo, c_lo) + AND(b_lo, XOR(d_lo, c_lo))) % 4294967296 + XOR(SHR(b_lo, 28) + SHL(b_hi, 4), SHL(b_lo, 30) + SHR(b_hi, 2), SHL(b_lo, 25) + SHR(b_hi, 7)) % 4294967296
            a_lo = tmp1 % 4294967296
            a_hi = z_hi + (AND(d_hi, c_hi) + AND(b_hi, XOR(d_hi, c_hi))) + XOR(SHR(b_hi, 28) + SHL(b_lo, 4), SHL(b_hi, 30) + SHR(b_lo, 2), SHL(b_hi, 25) + SHR(b_lo, 7)) + (tmp1 - a_lo) / 4294967296
         end
         a_lo = h1_lo + a_lo
         h1_lo = a_lo % 4294967296
         h1_hi = (h1_hi + a_hi + (a_lo - h1_lo) / 4294967296) % 4294967296
         a_lo = h2_lo + b_lo
         h2_lo = a_lo % 4294967296
         h2_hi = (h2_hi + b_hi + (a_lo - h2_lo) / 4294967296) % 4294967296
         a_lo = h3_lo + c_lo
         h3_lo = a_lo % 4294967296
         h3_hi = (h3_hi + c_hi + (a_lo - h3_lo) / 4294967296) % 4294967296
         a_lo = h4_lo + d_lo
         h4_lo = a_lo % 4294967296
         h4_hi = (h4_hi + d_hi + (a_lo - h4_lo) / 4294967296) % 4294967296
         a_lo = h5_lo + e_lo
         h5_lo = a_lo % 4294967296
         h5_hi = (h5_hi + e_hi + (a_lo - h5_lo) / 4294967296) % 4294967296
         a_lo = h6_lo + f_lo
         h6_lo = a_lo % 4294967296
         h6_hi = (h6_hi + f_hi + (a_lo - h6_lo) / 4294967296) % 4294967296
         a_lo = h7_lo + g_lo
         h7_lo = a_lo % 4294967296
         h7_hi = (h7_hi + g_hi + (a_lo - h7_lo) / 4294967296) % 4294967296
         a_lo = h8_lo + h_lo
         h8_lo = a_lo % 4294967296
         h8_hi = (h8_hi + h_hi + (a_lo - h8_lo) / 4294967296) % 4294967296
      end
      H_lo[1], H_lo[2], H_lo[3], H_lo[4], H_lo[5], H_lo[6], H_lo[7], H_lo[8] = h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo
      H_hi[1], H_hi[2], H_hi[3], H_hi[4], H_hi[5], H_hi[6], H_hi[7], H_hi[8] = h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi
   end

   function md5_feed_64(H, K, str, offs, size)
      -- offs >= 0, size >= 0, size is multiple of 64
      local W, md5_next_shift = common_W, md5_next_shift
      local h1, h2, h3, h4 = H[1], H[2], H[3], H[4]
      for pos = offs, offs + size - 1, 64 do
         for j = 1, 16 do
            pos = pos + 4
            local a, b, c, d = byte(str, pos - 3, pos)
            W[j] = ((d * 256 + c) * 256 + b) * 256 + a
         end
         local a, b, c, d = h1, h2, h3, h4
         local s = 32-7
         for j = 1, 16 do
            local F = ROR(AND(b, c) + AND(-1-b, d) + a + K[j] + W[j], s) + b
            s = md5_next_shift[s]
            a = d
            d = c
            c = b
            b = F
         end
         s = 32-5
         for j = 17, 32 do
            local F = ROR(AND(d, b) + AND(-1-d, c) + a + K[j] + W[(5*j-4) % 16 + 1], s) + b
            s = md5_next_shift[s]
            a = d
            d = c
            c = b
            b = F
         end
         s = 32-4
         for j = 33, 48 do
            local F = ROR(XOR(XOR(b, c), d) + a + K[j] + W[(3*j+2) % 16 + 1], s) + b
            s = md5_next_shift[s]
            a = d
            d = c
            c = b
            b = F
         end
         s = 32-6
         for j = 49, 64 do
            local F = ROR(XOR(c, OR(b, -1-d)) + a + K[j] + W[(j*7-7) % 16 + 1], s) + b
            s = md5_next_shift[s]
            a = d
            d = c
            c = b
            b = F
         end
         h1 = (a + h1) % 4294967296
         h2 = (b + h2) % 4294967296
         h3 = (c + h3) % 4294967296
         h4 = (d + h4) % 4294967296
      end
      H[1], H[2], H[3], H[4] = h1, h2, h3, h4
   end

   function sha1_feed_64(H, str, offs, size)
      -- offs >= 0, size >= 0, size is multiple of 64
      local W = common_W
      local h1, h2, h3, h4, h5 = H[1], H[2], H[3], H[4], H[5]
      for pos = offs, offs + size - 1, 64 do
         for j = 1, 16 do
            pos = pos + 4
            local a, b, c, d = byte(str, pos - 3, pos)
            W[j] = ((a * 256 + b) * 256 + c) * 256 + d
         end
         for j = 17, 80 do
            W[j] = ROL(XOR(W[j-3], W[j-8], W[j-14], W[j-16]), 1)
         end
         local a, b, c, d, e = h1, h2, h3, h4, h5
         for j = 1, 20 do
            local z = ROL(a, 5) + AND(b, c) + AND(-1-b, d) + 0x5A827999 + W[j] + e        -- constant = floor(2^30 * sqrt(2))
            e = d
            d = c
            c = ROR(b, 2)
            b = a
            a = z
         end
         for j = 21, 40 do
            local z = ROL(a, 5) + XOR(b, c, d) + 0x6ED9EBA1 + W[j] + e                    -- 2^30 * sqrt(3)
            e = d
            d = c
            c = ROR(b, 2)
            b = a
            a = z
         end
         for j = 41, 60 do
            local z = ROL(a, 5) + AND(d, c) + AND(b, XOR(d, c)) + 0x8F1BBCDC + W[j] + e   -- 2^30 * sqrt(5)
            e = d
            d = c
            c = ROR(b, 2)
            b = a
            a = z
         end
         for j = 61, 80 do
            local z = ROL(a, 5) + XOR(b, c, d) + 0xCA62C1D6 + W[j] + e                    -- 2^30 * sqrt(10)
            e = d
            d = c
            c = ROR(b, 2)
            b = a
            a = z
         end
         h1 = (a + h1) % 4294967296
         h2 = (b + h2) % 4294967296
         h3 = (c + h3) % 4294967296
         h4 = (d + h4) % 4294967296
         h5 = (e + h5) % 4294967296
      end
      H[1], H[2], H[3], H[4], H[5] = h1, h2, h3, h4, h5
   end

end

--------------------------------------------------------------------------------
-- MAGIC NUMBERS CALCULATOR
--------------------------------------------------------------------------------
-- Q:
--    Is 53-bit "double" math enough to calculate square roots and cube roots of primes with 64 correct bits after decimal point?
-- A:
--    Yes, 53-bit "double" arithmetic is enough.
--    We could obtain first 40 bits by direct calculation of p^(1/3) and next 40 bits by one step of Newton's method.

do
   local function mul(src1, src2, factor, result_length)
      -- src1, src2 - long integers (arrays of digits in base 2^24)
      -- factor - small integer
      -- returns long integer result (src1 * src2 * factor) and its floating point approximation
      local result, carry, value, weight = {}, 0.0, 0.0, 1.0
      for j = 1, result_length do
         for k = math.max(1, j + 1 - #src2), math.min(j, #src1) do
            carry = carry + factor * src1[k] * src2[j + 1 - k]  -- "int32" is not enough for multiplication result, that's why "factor" must be of type "double"
         end
         local digit = carry % 2^24
         result[j] = floor(digit)
         carry = (carry - digit) / 2^24
         value = value + digit * weight
         weight = weight * 2^24
      end
      return result, value
   end

   local idx, step, p, one, sqrt_hi, sqrt_lo = 0, {4, 1, 2, -2, 2}, 4, {1}, sha2_H_hi, sha2_H_lo
   repeat
      p = p + step[p % 6]
      local d = 1
      repeat
         d = d + step[d % 6]
         if d*d > p then -- next prime number is found
            local root = p^(1/3)
            local R = root * 2^40
            R = mul({R - R % 1}, one, 1.0, 2)
            local _, delta = mul(R, mul(R, R, 1.0, 4), -1.0, 4)
            local hi = R[2] % 65536 * 65536 + floor(R[1] / 256)
            local lo = R[1] % 256 * 16777216 + floor(delta * (2^-56 / 3) * root / p)
            if idx < 16 then
               root = p^(1/2)
               R = root * 2^40
               R = mul({R - R % 1}, one, 1.0, 2)
               _, delta = mul(R, R, -1.0, 2)
               local hi = R[2] % 65536 * 65536 + floor(R[1] / 256)
               local lo = R[1] % 256 * 16777216 + floor(delta * 2^-17 / root)
               local idx = idx % 8 + 1
               sha2_H_ext256[224][idx] = lo
               sqrt_hi[idx], sqrt_lo[idx] = hi, lo + hi * hi_factor
               if idx > 7 then
                  sqrt_hi, sqrt_lo = sha2_H_ext512_hi[384], sha2_H_ext512_lo[384]
               end
            end
            idx = idx + 1
            sha2_K_hi[idx], sha2_K_lo[idx] = hi, lo % K_lo_modulo + hi * hi_factor
            break
         end
      until p % d == 0
   until idx > 79
end

-- Calculating IVs for SHA512/224 and SHA512/256
for width = 224, 256, 32 do
   local H_lo, H_hi = {}
   if XOR64A5 then
      for j = 1, 8 do
         H_lo[j] = XOR64A5(sha2_H_lo[j])
      end
   else
      H_hi = {}
      for j = 1, 8 do
         H_lo[j] = XOR32A5(sha2_H_lo[j])
         H_hi[j] = XOR32A5(sha2_H_hi[j])
      end
   end
   sha512_feed_128(H_lo, H_hi, sha2_K_lo, sha2_K_hi, "SHA-512/"..tonumber(width).."\128"..string_rep("\0", 115).."\88", 0, 128)
   sha2_H_ext512_lo[width] = H_lo
   sha2_H_ext512_hi[width] = H_hi
end

-- Constants for MD5
do
   local sin, abs, modf = math.sin, math.abs, math.modf
   for idx = 1, 64 do
      -- we can't use formula floor(abs(sin(idx))*2^32) because its result may be not an integer on Lua built with 32-bit integers
      local hi, lo = modf(abs(sin(idx)) * 2^16)
      md5_K[idx] = hi * 65536 + floor(lo * 2^16)
   end
end

--------------------------------------------------------------------------------
-- MAIN FUNCTIONS
--------------------------------------------------------------------------------

local function sha256ext(width, text)

   -- Create an instance (private objects for current calculation)
   local H, length, tail = {unpack(sha2_H_ext256[width])}, 0.0, ""

   local function partial(text_part)
      if text_part then
         if tail then
            length = length + #text_part
            local offs = 0
            if tail ~= "" and #tail + #text_part >= 64 then
               offs = 64 - #tail
               sha256_feed_64(H, sha2_K_hi, tail..sub(text_part, 1, offs), 0, 64)
               tail = ""
            end
            local size = #text_part - offs
            local size_tail = size % 64
            sha256_feed_64(H, sha2_K_hi, text_part, offs, size - size_tail)
            tail = tail..sub(text_part, #text_part + 1 - size_tail)
            return partial
         else
            error("Adding more chunks is not allowed after receiving the result", 2)
         end
      else
         if tail then
            local final_blocks = {tail, "\128", string_rep("\0", (-9 - length) % 64 + 1)}
            tail = nil
            -- Assuming user data length is shorter than (2^53)-9 bytes
            -- Anyway, it looks very unrealistic that someone would spend more than a year of calculations to process 2^53 bytes of data by using this Lua script :-)
            -- 2^53 bytes = 2^56 bits, so "bit-counter" fits in 7 bytes
            length = length * (8 / 256^7)  -- convert "byte-counter" to "bit-counter" and move decimal point to the left
            for j = 4, 10 do
               length = length % 1 * 256
               final_blocks[j] = char(floor(length))
            end
            final_blocks = table_concat(final_blocks)
            sha256_feed_64(H, sha2_K_hi, final_blocks, 0, #final_blocks)
            local max_reg = width / 32
            for j = 1, max_reg do
               H[j] = HEX(H[j])
            end
            H = table_concat(H, "", 1, max_reg)
         end
         return H
      end
   end

   if text then
      -- Actually perform calculations and return the SHA256 digest of a message
      return partial(text)()
   else
      -- Return function for chunk-by-chunk loading
      -- User should feed every chunk of input data as single argument to this function and finally get SHA256 digest by invoking this function without an argument
      return partial
   end

end


local function sha512ext(width, text)

   -- Create an instance (private objects for current calculation)
   local length, tail, H_lo, H_hi = 0.0, "", { unpack(sha2_H_ext512_lo[width]) }, not HEX64 and { unpack(sha2_H_ext512_hi[width]) }

   local function partial(text_part)
      if text_part then
         if tail then
            length = length + #text_part
            local offs = 0
            if tail ~= "" and #tail + #text_part >= 128 then
               offs = 128 - #tail
               sha512_feed_128(H_lo, H_hi, sha2_K_lo, sha2_K_hi, tail..sub(text_part, 1, offs), 0, 128)
               tail = ""
            end
            local size = #text_part - offs
            local size_tail = size % 128
            sha512_feed_128(H_lo, H_hi, sha2_K_lo, sha2_K_hi, text_part, offs, size - size_tail)
            tail = tail..sub(text_part, #text_part + 1 - size_tail)
            return partial
         else
            error("Adding more chunks is not allowed after receiving the result", 2)
         end
      else
         if tail then
            local final_blocks = {tail, "\128", string_rep("\0", (-17-length) % 128 + 9)}
            tail = nil
            -- Assuming user data length is shorter than (2^53)-17 bytes
            -- 2^53 bytes = 2^56 bits, so "bit-counter" fits in 7 bytes
            length = length * (8 / 256^7)  -- convert "byte-counter" to "bit-counter" and move floating point to the left
            for j = 4, 10 do
               length = length % 1 * 256
               final_blocks[j] = char(floor(length))
            end
            final_blocks = table_concat(final_blocks)
            sha512_feed_128(H_lo, H_hi, sha2_K_lo, sha2_K_hi, final_blocks, 0, #final_blocks)
            local max_reg = ceil(width / 64)
            if HEX64 then
               for j = 1, max_reg do
                  H_lo[j] = HEX64(H_lo[j])
               end
            else
               for j = 1, max_reg do
                  H_lo[j] = HEX(H_hi[j])..HEX(H_lo[j])
               end
               H_hi = nil
            end
            H_lo = sub(table_concat(H_lo, "", 1, max_reg), 1, width / 4)
         end
         return H_lo
      end
   end

   if text then
      -- Actually perform calculations and return the SHA512 digest of a message
      return partial(text)()
   else
      -- Return function for chunk-by-chunk loading
      -- User should feed every chunk of input data as single argument to this function and finally get SHA512 digest by invoking this function without an argument
      return partial
   end

end


local function md5(text)

   -- Create an instance (private objects for current calculation)
   local H, length, tail = {unpack(md5_sha1_H, 1, 4)}, 0.0, ""

   local function partial(text_part)
      if text_part then
         if tail then
            length = length + #text_part
            local offs = 0
            if tail ~= "" and #tail + #text_part >= 64 then
               offs = 64 - #tail
               md5_feed_64(H, md5_K, tail..sub(text_part, 1, offs), 0, 64)
               tail = ""
            end
            local size = #text_part - offs
            local size_tail = size % 64
            md5_feed_64(H, md5_K, text_part, offs, size - size_tail)
            tail = tail..sub(text_part, #text_part + 1 - size_tail)
            return partial
         else
            error("Adding more chunks is not allowed after receiving the result", 2)
         end
      else
         if tail then
            local final_blocks = {tail, "\128", string_rep("\0", (-9 - length) % 64)}
            tail = nil
            length = length * 8  -- convert "byte-counter" to "bit-counter"
            for j = 4, 11 do
               local low_byte = length % 256
               final_blocks[j] = char(low_byte)
               length = (length - low_byte) / 256
            end
            final_blocks = table_concat(final_blocks)
            md5_feed_64(H, md5_K, final_blocks, 0, #final_blocks)
            for j = 1, 4 do
               H[j] = HEX(H[j])
            end
            H = gsub(table_concat(H), "(..)(..)(..)(..)", "%4%3%2%1")
         end
         return H
      end
   end

   if text then
      -- Actually perform calculations and return the MD5 digest of a message
      return partial(text)()
   else
      -- Return function for chunk-by-chunk loading
      -- User should feed every chunk of input data as single argument to this function and finally get MD5 digest by invoking this function without an argument
      return partial
   end

end


local function sha1(text)

   -- Create an instance (private objects for current calculation)
   local H, length, tail = {unpack(md5_sha1_H)}, 0.0, ""

   local function partial(text_part)
      if text_part then
         if tail then
            length = length + #text_part
            local offs = 0
            if tail ~= "" and #tail + #text_part >= 64 then
               offs = 64 - #tail
               sha1_feed_64(H, tail..sub(text_part, 1, offs), 0, 64)
               tail = ""
            end
            local size = #text_part - offs
            local size_tail = size % 64
            sha1_feed_64(H, text_part, offs, size - size_tail)
            tail = tail..sub(text_part, #text_part + 1 - size_tail)
            return partial
         else
            error("Adding more chunks is not allowed after receiving the result", 2)
         end
      else
         if tail then
            local final_blocks = {tail, "\128", string_rep("\0", (-9 - length) % 64 + 1)}
            tail = nil
            -- Assuming user data length is shorter than (2^53)-9 bytes
            -- 2^53 bytes = 2^56 bits, so "bit-counter" fits in 7 bytes
            length = length * (8 / 256^7)  -- convert "byte-counter" to "bit-counter" and move decimal point to the left
            for j = 4, 10 do
               length = length % 1 * 256
               final_blocks[j] = char(floor(length))
            end
            final_blocks = table_concat(final_blocks)
            sha1_feed_64(H, final_blocks, 0, #final_blocks)
            for j = 1, 5 do
               H[j] = HEX(H[j])
            end
            H = table_concat(H)
         end
         return H
      end
   end

   if text then
      -- Actually perform calculations and return the SHA-1 digest of a message
      return partial(text)()
   else
      -- Return function for chunk-by-chunk loading
      -- User should feed every chunk of input data as single argument to this function and finally get SHA-1 digest by invoking this function without an argument
      return partial
   end

end


local function hex2bin(hex_string)
   return (gsub(hex_string, "%x%x",
      function (hh)
         return char(tonumber(hh, 16))
      end
   ))
end


local block_size_for_HMAC  -- a table, will be defined at the end of the module

local function pad_and_xor(str, result_length, byte_for_xor)
   return gsub(str, ".",
      function(c)
         return char(XOR_BYTE(byte(c), byte_for_xor))
      end
   )..string_rep(char(byte_for_xor), result_length - #str)
end

local function hmac(hash_func, key, message)

   -- Create an instance (private objects for current calculation)
   local block_size = block_size_for_HMAC[hash_func]
   if not block_size then
      error("Unknown hash function", 2)
   end
   if #key > block_size then
      key = hex2bin(hash_func(key))
   end
   local append = hash_func()(pad_and_xor(key, block_size, 0x36))
   local result

   local function partial(message_part)
      if not message_part then
         result = result or hash_func(pad_and_xor(key, block_size, 0x5C)..hex2bin(append()))
         return result
      elseif result then
         error("Adding more chunks is not allowed after receiving the result", 2)
      else
         append(message_part)
         return partial
      end
   end

   if message then
      -- Actually perform calculations and return the HMAC of a message
      return partial(message)()
   else
      -- Return function for chunk-by-chunk loading of a message
      -- User should feed every chunk of the message as single argument to this function and finally get HMAC by invoking this function without an argument
      return partial
   end

end

local bin2base64, base642bin
do
   local base64_symbols = {
      ['+'] = 62, ['-'] = 62,  [62] = '+',
      ['/'] = 63, ['_'] = 63,  [63] = '/',
      ['='] = -1, ['.'] = -1,  [-1] = '='
   }
   local symbol_index = 0
   for j, pair in ipairs{'AZ', 'az', '09'} do
      for ascii = byte(pair), byte(pair, 2) do
         local ch = char(ascii)
         base64_symbols[ch] = symbol_index
         base64_symbols[symbol_index] = ch
         symbol_index = symbol_index + 1
      end
   end

   function bin2base64(binary_string)
      local result = {}
      for pos = 1, #binary_string, 3 do
         local c1, c2, c3, c4 = byte(sub(binary_string, pos, pos + 2)..'\0', 1, -1)
         result[#result + 1] =
            base64_symbols[floor(c1 / 4)]
            ..base64_symbols[c1 % 4 * 16 + floor(c2 / 16)]
            ..base64_symbols[c3 and c2 % 16 * 4 + floor(c3 / 64) or -1]
            ..base64_symbols[c4 and c3 % 64 or -1]
      end
      return table_concat(result)
   end
   
   function base642bin(base64_string)
      local result, chars_qty = {}, 3
      for pos, ch in gmatch(gsub(base64_string, '%s+', ''), '()(.)') do
         local code = base64_symbols[ch]
         if code < 0 then
            chars_qty = chars_qty - 1
            code = 0
         end
         local idx = pos % 4
         if idx > 0 then
            result[-idx] = code
         else
            local c1 = result[-1] * 4 + floor(result[-2] / 16)
            local c2 = (result[-2] % 16) * 16 + floor(result[-3] / 4)
            local c3 = (result[-3] % 4) * 64 + code
            result[#result + 1] = sub(char(c1, c2, c3), 1, chars_qty)
         end
      end
      return table_concat(result)
   end
   
end   


local sha2 = {
   -- SHA2 hash functions:
   sha256     = function (text) return sha256ext(256, text) end,  -- SHA-256
   sha224     = function (text) return sha256ext(224, text) end,  -- SHA-224
   sha512     = function (text) return sha512ext(512, text) end,  -- SHA-512
   sha384     = function (text) return sha512ext(384, text) end,  -- SHA-384
   sha512_224 = function (text) return sha512ext(224, text) end,  -- SHA-512/224
   sha512_256 = function (text) return sha512ext(256, text) end,  -- SHA-512/256
   -- other hash functions:
   md5        = md5,                                              -- MD5
   sha1       = sha1,                                             -- SHA-1
   -- misc utilities:
   hmac       = hmac,                                             -- HMAC (applicable to any hash function from this module)
   hex2bin    = hex2bin,                                          -- converts hexadecimal representation to binary string
   base642bin = base642bin,                                       -- converts base64 representation to binary string
   bin2base64 = bin2base64,                                       -- converts binary string to base64 representation
}

block_size_for_HMAC = {
   [sha2.sha256]     = 64,  -- SHA-256
   [sha2.sha224]     = 64,  -- SHA-224
   [sha2.sha512]     = 128, -- SHA-512
   [sha2.sha384]     = 128, -- SHA-384
   [sha2.sha512_224] = 128, -- SHA-512/224
   [sha2.sha512_256] = 128, -- SHA-512/256
   [sha2.md5]        = 64,  -- MD5
   [sha2.sha1]       = 64,  -- SHA-1
}

return sha2
