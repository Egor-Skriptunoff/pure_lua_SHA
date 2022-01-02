--------------------------------------------------------------------------------
-- TESTS of the module "sha2.lua"
--------------------------------------------------------------------------------

local sha = require"sha2"


local function test_sha256()

   local sha256 = sha.sha256

   -- some test strings
   assert(sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
   assert(sha256("123456") == "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92")
   assert(sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
   assert(sha256("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") == "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
   assert(sha256("The quick brown fox jumps over the lazy dog") == "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")
   assert(sha256("The quick brown fox jumps over the lazy cog") == "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be")

   -- chunk-by-chunk loading:   sha256("string") == sha256()("st")("ri")("ng")()
   local append_next_chunk = sha256() -- create a private closure for calculating digest of single string
   append_next_chunk("The quick brown fox")
   append_next_chunk(" jumps ")
   append_next_chunk("")              -- chunk may be an empty string
   append_next_chunk("over the lazy dog")
   assert(append_next_chunk() == "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")  -- invocation without an argument means "give me the result"
   assert(append_next_chunk() == "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")  -- you can ask the same result multiple times if needed
   assert(not pcall(append_next_chunk, "more text"))  -- no more chunks are allowed after receiving the result, append_next_chunk("more text") will fail

   -- one-liner is possible due to "append_next_chunk(chunk)" returns the function "append_next_chunk"
   assert(sha256()("The quick brown fox")(" jumps ")("")("over the lazy dog")() == "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")

   -- empty string
   assert(sha256("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
   assert(sha256()() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

   -- two parallel computations don't interfere with each other
   local chunk_for_digits = sha256()
   chunk_for_digits("123")
   local chunk_for_fox = sha256()
   chunk_for_fox("The quick brown fox jumps ")
   chunk_for_digits("45")
   chunk_for_fox("over the lazy dog")
   chunk_for_digits("6")
   assert(chunk_for_digits() == "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92")
   assert(chunk_for_fox() == "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")

   -- "00...0\n"
   for i, dgst in pairs{  -- from 50 to 70 zeroes
      [50] = "9660acb8046abf46cf27280e61abd174ebac98ad6855e093772b78df85523129",
      [51] = "31e1c552b357ace9bcb924691799a3c0d3aa10d8b428d9de28a278e3c79ecb7b",
      [52] = "0be5c4bcb6f47e30c13515594dbef4faa3a6485af67c177179fee8b33cd4f2a0",
      [53] = "d368c7f6038c1743bdbfe6a9c3a72d4e6916aa219ed8d559766c9e8f9845f3b8",
      [54] = "7080a4aa6ff030ae152fe610a62ee29464f92afeb176474551a69d35aab154a0",
      [55] = "149c1cda81fa9359c0c2a5e405ca972986f1d53e05f6282871dd1581046b3f44",
      [56] = "eb2d4d41948ce546c8adff07ee97342070c5b89789f616a33efe52c7d3ec73d4",
      [57] = "c831db596ccbbf248023461b1c05d3ae084bcc79bcb2626c5ec179fb34371f2a",
      [58] = "1345b8a930737b1069bbf9b891ce095850f6cdba6e25874ea526a2ccb611fe46",
      [59] = "380ad21e466885fae080ceeada75ac04944687e626e161c0b24e91af3eec2def",
      [60] = "b9ab06fa30ef8531c5eee11651aa86f8279a245e0a3c29bf6228c59475cc610a",
      [61] = "bcc187de6605d9e11a0cc6edf02b67fb651fe1779ec59438788093d8e376c07c",
      [62] = "ae0b3681157b83b34de8591d2453915e40c3105ae79434e241d82d4035218e01",
      [63] = "68a27b4735f6806fb5983c1805a23797aa93ea06e0ebcb6daada2ea1ab5a05af",
      [64] = "827d096d92f3deeaa0e8070d79f45beb176768e57a958a1cd325f5f4b754b048",
      [65] = "6c7bd8ec0fe9b4e05a2d27dd5e41a8687a9716a2e8926bdfa141266b12942ec1",
      [66] = "2f4b4c41017a2ddd1cc8cd75478a82e9452e445d4242f09782535376d6f4ba50",
      [67] = "b777b86e005807a446ead00986fcbf3bdd6c022524deabf017eeb3f0c30b6eed",
      [68] = "777da331f60c793f582e4ca33223778218ddfd241981f15be5886171fb8301b5",
      [69] = "06ed0c4cbf7d2b38de5f01eab2d2cd552d9cb87f97b714b96bb7a9d1b6117c6d",
      [70] = "e82223344d5f3c024514cfbe6d478b5df98bb878f34d7a07e7b064fa7fa91946"
   } do
      assert(sha256(("0"):rep(i).."\n") == dgst)
   end

   -- "aa...a"
   assert(sha256(("a"):rep(55)) == "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318")
   assert(sha256(("a"):rep(56)) == "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a")

   -- negative byte values
   assert(sha256(("\255"):rep(1e3)) == "b4f73dff046400b76728ab32619e3d89e00132653725f660c62ab9fca975b372")

   -- "aa...a\n" in "chunk-by-chunk" mode
   local next_chunk = sha256()
   for i = 1, 65 do
      next_chunk("a")
   end
   next_chunk("\n")
   assert(next_chunk() == "574883a9977284a46845620eaa55c3fa8209eaa3ebffe44774b6eb2dba2cb325")
   -- "aa...a\n" in "whole-string" mode
   assert(sha256(("a"):rep(65).."\n") == "574883a9977284a46845620eaa55c3fa8209eaa3ebffe44774b6eb2dba2cb325")

   local function split_and_calculate_sha256(s, len) -- split string s in chunks of length len
      local next_chunk = sha256()
      for idx = 1, #s, len do
         next_chunk(s:sub(idx, idx + len - 1))
      end
      return next_chunk()
   end
   -- "00...0\n00...0\n...00...0\n" (80 lines of 80 zeroes each) in chunk-by-chunk mode with different chunk lengths
   local s = (("0"):rep(80).."\n"):rep(80)
   assert(split_and_calculate_sha256(s, 1)   == "736c7a8b17e2cfd44a3267a844db1a8a3e8988d739e3e95b8dd32678fb599139")
   assert(split_and_calculate_sha256(s, 2)   == "736c7a8b17e2cfd44a3267a844db1a8a3e8988d739e3e95b8dd32678fb599139")
   assert(split_and_calculate_sha256(s, 7)   == "736c7a8b17e2cfd44a3267a844db1a8a3e8988d739e3e95b8dd32678fb599139")
   assert(split_and_calculate_sha256(s, 70)  == "736c7a8b17e2cfd44a3267a844db1a8a3e8988d739e3e95b8dd32678fb599139")
   assert(split_and_calculate_sha256(s, 1e6) == "736c7a8b17e2cfd44a3267a844db1a8a3e8988d739e3e95b8dd32678fb599139")

end


local function test_sha512()

   local sha512 = sha.sha512

   assert(sha512("abc") == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
   assert(sha512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") == "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")

   -- "aa...a"
   for i, dgst in ipairs{  -- from 1 to 140 letters "a"
      [001] = "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
      [002] = "f6c5600ed1dbdcfdf829081f5417dccbbd2b9288e0b427e65c8cf67e274b69009cd142475e15304f599f429f260a661b5df4de26746459a3cef7f32006e5d1c1",
      [003] = "d6f644b19812e97b5d871658d6d3400ecd4787faeb9b8990c1e7608288664be77257104a58d033bcf1a0e0945ff06468ebe53e2dff36e248424c7273117dac09",
      [004] = "1b86355f13a7f0b90c8b6053c0254399994dfbb3843e08d603e292ca13b8f672ed5e58791c10f3e36daec9699cc2fbdc88b4fe116efa7fce016938b787043818",
      [005] = "f368a29b71bd201a7ef78b5df88b1361fbe83f959756d33793837a5d7b2eaf660f2f6c7e2fbace01965683c4cfafded3ff28aab34e329aa79bc81e7703f68b86",
      [006] = "7a9b2a35095dcdfedfdf0ef810310b409e38c92c20cbd51088ea5e4bc4873bdacfeb29f14b7f2ed033d87fad00036da83d5c597a7e7429bc70cec378db4de6a6",
      [007] = "d1ff70451d1f0b94f551461c5ca239e498f571add4542c381e3eef84eac24aea6d12f8333ef4a05847e205ef4bb094921314364e7648176f567863d982042a85",
      [008] = "f74f2603939a53656948480ce71f1ce466685b6654fd22c61c1f2ce4e2c96d1cd02d162b560c4beaf1ae45f3471dc5cbc1ce040701c0b5c38457988aa00fe97f",
      [009] = "507294e03fdbc784dc3f575706c3ce53b3c4c37065e89ddd6b6de8bd2be655e15412e27695d32d2d6a3a0eaabe36ebddde78af0122a65ec41128c98c6fd30554",
      [010] = "4714870aff6c97ca09d135834fdb58a6389a50c11fef8ec4afef466fb60a23ac6b7a9c92658f14df4993d6b40a4e4d8424196afc347e97640d68de61e1cf14b0",
      [011] = "2d5be0f423fee59bf2149f996e72d9f5f8df90540a7d23b68c0d0d9a9a32d2c144891ca8fe4a3c713cb6eb2991578541dad291ba623dbd7107c6a891ba00bcc8",
      [012] = "a88ac22ca41e71e252c1f0d925de1ec174346e097c695e948d23016ab54cf21da6f0b0490ffa752bcc4893afc0c2caa64307705d1996f2959a3e03dc420c68cf",
      [013] = "b0b8828df9473f2763f9a48b0a9683451e98155436c2eff64c628fedbba0cca2360312271f3971f2969b1f828b1bb8251d3a43e12361824aca14f9a9affe2171",
      [014] = "831ce89c92608efda86cdf89d36e855bc73c5d17b2162c0013c14a2676ef4794dc53de6a54c1e3fb782acef5dd1192d36d0ab7fa88262cf0f6a16950e44a828c",
      [015] = "0b6f7fb0679a1ef009d5c8c70551d3b7013a5881b41ec2d597c3cf22e6aa13a1cf9a925b7a012feb67956c83b91cc32bef1de4cdbc6b2ff0cffbba319b54d15e",
      [016] = "987d0fc93db6a73fdb16493690fb42455c7c6fbafe9a276965424b12afad3512fb808d902faa8a019d639dc5ad07c235805e08f396147cf435913cfed501f65a",
      [017] = "06ef0364617146f6200c2cbc4280202226d701c2961940f57e7b60677587c66087f23bbcffa0de8692221f9434ac9a21e6df6428377cd145e1a456e2359d2cf6",
      [018] = "10dbd292472d3ff7279f3dac7fdb83c296bd61cbe80b0e26fbc14f871fd9771180d83879e812ec9841ba15a110e84a589c0eedfc14427c23ba56fa4fb7773de0",
      [019] = "1d383178e64d7071e749b2d560a22abc97e6514c31e800b5cc12c6f72ad43a9a0c4ce7db246219f3dea09afae6044a484de203148cb55f1057ee37b9420073bb",
      [020] = "d87a10a0bee363dcdf764831e807df5ee5500483c09056b38f854606f9e665566264b15af9fee8f9b84f3a7b6ddb67b92996ef790d10e899ba0758d5ab650caf",
      [021] = "1f60925cd5271a8ec9eb49ea4bf187f6a7dbc22eeb0e2dbc89d8381d0e73dea5bff5375a6db7e49fc427cb4fdf9f7ece577037adf91decfc38f303b1cb79ad44",
      [022] = "0ff3b2ffbda4cf938263e9449735618103a4d6a0cdeeda57367f6377d23849c3dce6851377f8f1b3d2ce3ff1dd6de0d64920d7790994782b4a8e2697e31f1900",
      [023] = "c6020ac00b701699227ccc9355156da0ad1d521ada5949cc89dd00661725be08fea4a2519ceb1e50acdd16e7127783f7ed5bfabe5238ce0da7ad2b4174c5509a",
      [024] = "e37ff6da226042c6fdd066c20f00e0d09c4f4dea104d8ea1fc513496ef24a0e17cd4bfb2e95781329a45d3885ca0e20f88e453dc9a4c4dc2acd0be756e3356b8",
      [025] = "4d272d73d4000f885ad1be048b7c7f92c2a8e5a01f30a96ed82849223606ad639f73155c85a128fbd2c26d3de30fb207e57b9f7ff21bfc79e0d7f0e2fb5189dc",
      [026] = "90cce547b76967676972c60e83944ffdc143078b6b40c722a0f2ac90d78eed0057843213076a9a7df528d0c0ebf3c00a91ae1c37f8850173fa2c03c41b6168ea",
      [027] = "4cea8c7ef657f9177c286081f8f016adae91a131a496e939ac86060e691afba57accc08ddbc423eb9d0817725faad9554c60f314929f30e881871e8782228918",
      [028] = "24077df741cb7ba88537d62c55fbff3ea81b603c31e6fd0d2e5d28e1a505f6192d5b2c1f98011152fef2c75901f66d489c045a4a3f98705c2b244c004f1579d4",
      [029] = "2af97e464526c024ef466db4616559919b769b350b7f6830ecfa5ffdeacd6eb570daf0ed25c0c56b194119f15247f63f5b94b54e01283b4b7a832586acac9e09",
      [030] = "abd9c33f8c791b27dd614e80ad77f1ff33c2621663b4dcbe5a88417a8b95b8d6788a9320678b589aa5b405897b2113523df1defa304953ea2ae1a229f2736450",
      [031] = "ad9e7ae1f68786c33ca713d4632b29ebcc9c9c040fc176ead8acb395a14c08324e824f7531f6a50ba0d4a17de958a08e54c9597dcc30781e22c0d953d06f9f4d",
      [032] = "020089a47cb0761c222c323aec2bdecdaa7a0d0ec094cda8c5755ba26844453c25b37e4bc98aab8adc55c9da75bcd83af62905d62e9044a5d64cd93d93b54b34",
      [033] = "d578a2d3fab982fbc7f1fa20630713c5a2a2cd9654a53822978d3efd2becc2a02e1fa1391dd11e139d1489aba688367ea9286e2a9ba8ef67009c80df81998614",
      [034] = "c1de14e1a09b03c688bd568ff4b4fa086baed2181d0d99a219fb937484ba67f093efe36966b0ea5209dadb6ef4f67c2d1f753d49c083a6241d2ab4557509404e",
      [035] = "cbb50e7e8a14cb9df08642609b6d737302d78cdcff74e1f53e895ae4a7cb093a571364dbbc2797962f54366ef65ead1c41a44ffe2ab0d56b7ae01e99a7a4e6fb",
      [036] = "85a564722dbefd268ed2e2e70fb377306c207a9c7edb634adcd79b8829aaad700c3a26cce44eba99aff46c4349f5e5056a87fcd2b63dd08b8b7b1f2f3ea06d6b",
      [037] = "ae77859a42c40e3973aa42bc8fbe8713444f65173580507d7c4bcc7c85d7f8c93204f433d506e912504ea37c766af17e649bdf6c8356f6e8e65bf4e9321987cb",
      [038] = "5b7c791e8018b14752ca7b91386d3ddbd3f9307a69ca71d977e274171aa5cae0b1a03960e842ca05fc0b95205a243fc8b28c36e4dd60ff000a47fb63547e6a0c",
      [039] = "f140bd9a11c309eb9da6ae1c8360cf2bc952a41a9ff228c066c0811df508313f59f1b6e6ffc6d14ef967f477c69463974aefd78d1c1dec9d8d35ff0c81dc29e8",
      [040] = "e411795f8b2a38c99a7b86c888f84c9b26d0f47f2c086d71a2c9282caf6a898820e2c1f3dc1fa45b20178da40f6cb7e4479d3d7155845ed7a4b8698b398f3d0c",
      [041] = "9178f65d74628c56ce3ace5b9ae7ecb84fc8a840ae33367a9c5534e6556301dc4fea4927d82289483496c39b929afb4a4ea92ded82c02057a7b8029828d8fb8d",
      [042] = "e11e1d056266f561bf3a9dede38228700e59971b3be992fea66a687887441976d8b29193707211dfb94dd1f7918473c3e99ff48a7c91068a1aaf7054febb9e2d",
      [043] = "acbaf243155ab6ca5f44c13061757fa060acbc5cf43d996b4f47209c22bf70c29af8dbc5c0a68ca45e42142db1540d2db70f6f27a917a3019dc92dadd0f639d6",
      [044] = "647b6deadb5aeb56e4087414fe2a76d6f57083dd6303a19e152445d108dc2bcd17926981d500b19b913b36a3b343b2e6781c805c1897664a218a2cfecc6a5238",
      [045] = "3ca97cdefcc384485ec2b6bebffe63d98f5675132a8b43d1f38bad4ff1982264fc4876ec637e918f855d855945b9b84eb82386bc6fc1e92695ec623001f8ddd1",
      [046] = "7b549433b4ef39abb90dcd3eb90c63562b7f3daa056670b2f712ebb7e9e78adfe7423e4b39810c1109fb640e84d32047468b155fe342d13e7f4d7ee019fa5922",
      [047] = "ec1d753e2280b8136b686ec81b03b3f8a7f98152868e3a68f0a2c456082c2faaa93c39ad573a6d21f4a3350df602249dc89ad28620d27ecc1d9e1f258badcd04",
      [048] = "bd582a787a21036df7049d501879977625601527d7ddd6f707463cb8b3839fbedbe233b8e69f1696d0e82b168d3491a3dbb6005b6224c198601dafbd50e14365",
      [049] = "4b4ff3bc763a976c16afdd8082efc7a5c98d60342f0ed5a654f567dacbc6414833e60ed1d6770bd42638fdae605c69be0219532125a186609f0825376ab59e45",
      [050] = "bdba173e58132092b0aa67ea5080f247e5b3710630a789c519b311f3848588f0bac8db3091ff8fd16875601636bef625e43b3d82cb51eb6693cdd1b2a5c872b8",
      [051] = "78a0eb5d7c0b05284056e1f19cbb42a99470bc81de4f9bc48708d28c5a877626e69167c58d4e840a7aa699bc6dddd972564d84ea502b41d83878e98e68f83c81",
      [052] = "a45021322d3f30747b3ceb7c1b1975ac4698984be76915f82cdeefe769f115d9dc5c70549e897b0ab8d5d61fc9e73ad1f7f49db39bb4e1298ac833d290eb1d04",
      [053] = "0b08accaae7044e54074fdcb7404a10c0703144d4499a644d9cfc60f973dc27dcdc65ac31750f7407ba96d025fb699e64ddcd1acd0dabafeeafccb5733225d3b",
      [054] = "07a2200290a2b7423a94f71892554b17196e2301e2e446ce09f65abcb45523268274128038925489671af9b899747b80e35a0a1b8613ecfb44e6be3152a2fd93",
      [055] = "b0220c772cbf6c1822e2cb38a437d0e1d58772417a4bbb21c961364f8b6143e05aa6316dca8d1d7b19e16448419076395f6086cb55101fbd6d5497b148e1745f",
      [056] = "962b64aae357d2a4fee3ded8b539bdc9d325081822b0bfc55583133aab44f18bafe11d72a7ae16c79ce2ba620ae2242d5144809161945f1367f41b3972e26e04",
      [057] = "d3115798e872fc1ca6b276368e8ea0926daec6ab1f8f08297e4348ff5f5fe4c6e5205413271babafd4929b070754bc5800e5db44790666ec4e2f6ac52a17e163",
      [058] = "2282084c042e92d7ba1a9e1ee5527762e91c4ffee7a8676c4a4a0facefad352bed2d3c322368cfe813186084c5386e9f22f803dfe0a1b424cab3e0a95a6dc3f9",
      [059] = "fd4eaf2071e8d9cf36688c3be714f5e363a5b4932f509914c613d1b8987d188e82cdd12b6ab07ea2f676fad1789275ef37253260a817a61079bc0ea567ee094a",
      [060] = "5ac08e89d884de3f086c60e8f36e754cf0ae9be2f018a87b7f71b15c81356410077eaa075010eb48959783ba490dc7c9fec53573848d8929bd5fc0574552f58f",
      [061] = "0202004b03bf7be513c96ef3fa6e48fce6e02f858d3bd95edba5adbdce60b2d7a4aa8700de15fc421b5e6847d8fb8be1bd24acd16314cfd94f0fa69ff6d637b4",
      [062] = "9814d48ae1bfd731b32f0a829f20507ec9bd6b77609053718f7e2053b53c7a264bbab6a96d3d54a7f9a736570d11b1f99afb1735149f43cfee9b6f87886d3ff6",
      [063] = "c1b0f5c6d3b03dfe4a2602e67242f54e344090b66e01100a469b129f583f016c7e27dddeaa438393dcc7ec54b0b57c9ba7af007f9b56db5f6fb677d972a31362",
      [064] = "01d35c10c6c38c2dcf48f7eebb3235fb5ad74a65ec4cd016e2354c637a8fb49b695ef3c1d6f7ae4cd74d78cc9c9bcac9d4f23a73019998a7f73038a5c9b2dbde",
      [065] = "b83086cd8494e55708ad7ecd82dfb4bca1bda61ecbb7caf0c68967902e709345e5d8305eb7ac0d588afc6cbb75161aa9c8c7e0ea986bd833dafe5e1ccd37345a",
      [066] = "f2f1cb2b1da21f7df43034baf8ec6bc992a46a022a40f81339240fdae572dbdf34fcf26e97cabc0e001c0aa65607b45585d107c48d676d6e2f389fd801d1fed7",
      [067] = "1b049c5022acb0a6f886cb607629db83dee7ee8f623f8f0fcf352b8f5052036cc7e992e9f79bc424173abb07df8ccfb058f13cfe2a14925a1bb67f4447dd8929",
      [068] = "6c450032dd6b928bdb327b9892d15808163d314aeff37089380ca01ee4b1c8db739f71de29446c385fc8e0f12482ccb04ca1572e243affc7d77ed7bbc083be0d",
      [069] = "73fa82cfc129fb937094b53346e04ff29e44c67250f6952b63ef561bc7cc1169fd94368a252ae408f496c17684145d65cd46ec9c5a03eb59ecc35f6a1d2fc159",
      [070] = "d7ef283e6194befc2498bbced7f58bdf60cfcf10011fc5817b69cb13d63725017aa1e632ea3c609f6a5eb8a057ddb82953538f3e2a738262a11ddcd47f13752d",
      [071] = "216d4ffba1e94e8f281b06feb558346eeb0ae567c0a1d0c56ba2df704f45b2a6e6d91f97c5c00ebbcdfeb14b438bd9e56f2eb36ca64d22392520f3496f28fef5",
      [072] = "7e076f0892677d21072e99258203151146d4bc78ad6ed68edc939ba080c473ab66b10d38834e33abde71830dbd8529d895c7ea5f5773f1457d7c71bc3824b7c8",
      [073] = "1a3d403b46c595edfb71d10b4cb9e1b9ce4e44e28db6ba2a0334195816b85e6eba147bc6160864a0fe28166f99148476893a031a38a814e7136497296865f3c9",
      [074] = "4c4c8dcd6ba88f47a51df4dabdf227c335d70d5f4941b76e698536693e53c50241ef0264ea6f6dc5527485ddbe7a76900405158e32fef5ed184919943148da67",
      [075] = "8ea2d14c839946461666ab0a5966a10886e29d0a890104b123bb94d0af9011d8a961681fb95df98d00d5d351985f61f2e2eba2d91fd8032566b856d8408a09b0",
      [076] = "c642ba36e76cc1660c342d163fb32e4be8482072e641dd6b3662c447ecbc24f1b5e16ad4b83eed093c6f5999f1b2a0086fc23526cef9241a5a052c720bb5afde",
      [077] = "b9451e8c39c4276c2192939d49cbcb2b85a048e4f38bb5d3282e24c417de893ac2ff0acdef20036ed4deddbb526f992cd56f992aaba93d4edd3a628a4e53c811",
      [078] = "9a8c06cf6123391e9ee4d2441b7e534fc9551c242fb2b96fad45a7210edc010c36704b9ca1a07e935e6ff1413768e2f27726b213b16961633341ea82d75c5df3",
      [079] = "54b998867e8ac0d3eebcbf2252c107ad6dc5b557db5b7cb65a147475db99831011878784a62678a6fada687705ef68d048047f05b51db9c09168c4a7ad877036",
      [080] = "cb8d0d18db405d9d964ab61d1a5c00024df3805a329bf1500bec74d3ec1f1d0574da0b86153c9d8e317603bdb09e46d54d44551992a2464f0335a8398a2f2aee",
      [081] = "2fe6df89dcac80c7a03c2bc39633c12ae2898019117aacf77e490fa54cb8deb34a0d29ce778ee4f674831921853a15b541773486d5ac785163744e6d24ba388d",
      [082] = "c3e410354f6f890d0f3027805da471340f91db2a858501059124d3175eb7d637ca3637f7f95bafde0d74d026be7bf086e48931e299d68edc43e0a7ac4eac75c4",
      [083] = "107068fb436d658c0a96157316af41d323e582ea9c81146933ead563bf2c2a05b2c77ceeef57c01cd09ec28f6507238e930b1b7241d731f83194440f9256e5a6",
      [084] = "62b5337f5be290d028dc41dde08682ed7b0a7a842eae36dc6f7220e220012aeca98b2dac28325d1f78beef84352689c07c3a45f549e98ba908b010abceca9978",
      [085] = "6b6f3ac1316d9e8d1505ad163b70077df1df92568139721b32c23e5d84dc2fd742a4bad56bf0efacb3f3e63bbfb08a829b16df8cc1799eb199cd5d56be2b9d52",
      [086] = "bf8ed43d3aeebeb9b00d91013fbbb463b2f4b13e7ffc42741aeb9f0190a91b0401bb4fac68cc009d314287876c54d2f18891e6eee86fbe7125171559be6a03d7",
      [087] = "056ffe9a8b3a346abb92cf36efb74417748a044c4ca07f94e7bb076eeafa67073a85fcc1b17e7953138f304bbea7d0592e910e55b489e22c9015dc4e04ba76dc",
      [088] = "a945652aabf28d5ed6bb284a35fd4296a9a0ddebc81bf59991759ecaa7fb95a59628cf1ae75c88177fa3993e0cd0f138a807cdc01d17ca3922817ad1dc1c39e7",
      [089] = "bb4ec00ac4a82ed71af3936559c5940582218da063554c6f3efbb6d67cc808a2d6dbf088d0f371a4a1259efb1f1edeefa8093cab25551519d7ac6142711e50fe",
      [090] = "3a60fa8bede0f822c5dea75eff151ed5841d11b301c474a13571aff2dd0e216b4bc072b9ce409a70c6e6ff35bcae2f0950880d943f95775dd8f54d94b12d47c3",
      [091] = "bed8ac47aef0271fe40227247ddcdfd6b4885effeba3042f34b6fd525ab56cbdf72050cb71b1d42ae0ee1c548b36668b9297279d661380dffa39e66aa2959f99",
      [092] = "dfecce5852f67e858304fc5dc0c15cb29e28c69af4e2c117d333ea46d2ef2b0379a983507bc16e827b86c2433404159b759de91eb9ae975f338bacf38ad20371",
      [093] = "51585d172675d427009ea1658ac2a4d67a600e65034cb7f8eb34a39add704b67ae0a2798b7d7e7a16ee0f6902a165a0646cd9fe1cc777a07c6bfa14028c8eec8",
      [094] = "9e4246d4d3725a67a909dd1a4f06c627627942c0bb31eb4c614cab842e6bfb9faa7e8938575a2402832ac353a6fb47f4918b31d754eb9764e714f6925462b54e",
      [095] = "89e0446c3ff5a04b6d707ef43a77e2b349791f402930dbdb74bbab73d5215e294146ba7bd2fa269aee38564ef11a9ccaf5278f9e82687126dcf20d481d470617",
      [096] = "39ba3c74b23cb7deffb5d59624e320c08692637057daaaeea4d847e1d3b6a2ce6895ff3c609d57da490484b030ed231d5bdfafcfe264bd3d91cddb39c2d036ab",
      [097] = "db3a1fb5909f50e02e1626616247de6867e9e332d0eeef4650367cf0058f4764eb4a3869d3931b5ef6fc7a044a868b5fa894462df15c3954e88cd70c9a1de1b2",
      [098] = "86497b815f64702e2ac6aca1f1d16f7159b4f0b34f6e92a41e632982a7291465957e0ef171042b9630bb66c6e35051613f99bdc95c371eeb46bff8c897eba6e9",
      [099] = "21883a9b2ffa353c93fea49ea8b92be22797e6e8b360ebac8ed894b702766458a825adf67d9561d6758f5f9cc3aec7a4b2e4464a08e6959029dbc0b2f3fc6105",
      [100] = "70ff99fd241905992cc3fff2f6e3f562c8719d689bfe0e53cbc75e53286d82d8767aed0959b8c63aadf55b5730babee75ea082e88414700d7507b988c44c47bc",
      [101] = "2327e3b2946432dd2f4bce390ca652ec5e90f44fced0e921f612cf6d594cfc5e21b56e30a30dc0157e2c37a59cd37951f20cb9e2bc2d815a2676c01c2f827d51",
      [102] = "ec90d76ee1a1643126f53609a2721ad4a130c57d4dd0416a5d1b0bc43419ed6b3b0e82e0ff5eb76e94accfacb8bf72d7c92b622a0842d9a5b8b6e40fa2fc5231",
      [103] = "48e257ba5ef0c4b0b9769d26d5990d87f058430e368802c1f9a47195a6fa23ede9bbadc4c46ef2a8480cbfa0ced25dad522ca1752a66d5b43a72486f82c7b934",
      [104] = "e4f39bcd76fe94bfa84b31b0b9f3d2fe065b1e01ff2c3c0cd6f26b942f3c73a35031b9ecb4d82418a52892dabb459b27f0ba04af5e90636edf0b2caaa2d7906a",
      [105] = "3b6dd73c9552f2381107bf206b49c7967fdc5f5011d877d9c576bb4da6d74fbbabf46a1105242d7c645978e54c0b44adaf06d9f7aa4703e8a58829f6d87c5168",
      [106] = "470edb01e9dc9db187acdc9fa594e35b40831f9ddf76309d4a99a7aef1f0d9f79b5a4c9a22a38aeca3a1c2d6ceaeb603899577a30643a97872717c025a9a4fdc",
      [107] = "8cfcdd655481cca50730fe51ee985e9b51946f1345cb6a1801e5e0ed64ef979f431d5a7c3bd2a479d6d82e354210741956d194ee0febbc132b35907f4e2be32f",
      [108] = "a53d93726f1ba688a57267326473eceddc4ccf992d5c53429ca3edd4b122b4fe0b0568887d65c220cbac93fc4f612f97a09eb95e9f903409c78a22eee4fa1781",
      [109] = "0cda6b04d9466bb7f3995c16732e1347f29c23a64fe0b085fadba0995644cc5aa71587423c274c10e09518310c5f866cfaceb229fabb574219f12182eb114182",
      [110] = "c825949632e509824543f7eaf159fb6041722fce3c1cdcbb613b3d37ff107c519417baac32f8e74fe29d7f4823bf6886956603dca5354a6ed6e4a542e06b7d28",
      [111] = "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2",
      [112] = "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca",
      [113] = "55ddd8ac210a6e18ba1ee055af84c966e0dbff091c43580ae1be703bdb85da31acf6948cf5bd90c55a20e5450f22fb89bd8d0085e39f85a86cc46abbca75e24d",
      [114] = "5e9eb0e4b270d086e77eeaf3ce8b1cfc615031b8c463dc34f5c139786f274f22accb4d89e8f40d1a0c2acc84c4dc0f2bab390a9d9495493bd617ed004271bb64",
      [115] = "eaa30f93760743ac7d0a6cb8ed5ef3b30c59097bc44d0ec337344301deba9fb92b20c488d55de415f6aaed0df4925b42894b81d2e1cde89d91ec7f6cc67262b4",
      [116] = "a8bff469314a1ce0c990bb3fd539d92accb6249cc674b559bc9d3898b7a126fee597197fa42c971443470053c7d7f54b09371a59b0f7af87b1917c5347e8f8e0",
      [117] = "c0c27aea8dbe169c4cf25176cbf12db708fd6303db8cf94a1cfb402c1680d3d68f39bc5b9a10970dd5373cb0fe1cb36fa50e33165140d72933ba87af9d5d1ffe",
      [118] = "d6f856c92a5a694dec299f5a4765bed80e4e7431aa5505f82b21584dd1f1fe970f698bec5a3f4faa593d1aac944a96c21b85463a773cdf3ad87c4a00fb9e5073",
      [119] = "130396a75cb483f2eee8c56d8a668bb3d2641f5243212c0bee2bd33da096ad9eb8179fe18f9eaacf76e09fae9de4c3f14ba13341e345be05bf76c182cc3468cb",
      [120] = "f241de612b01aa2fa3cf01531d2a8e5e17fc761dfd48a704a834a47f57d6eade7804ecc39be42fdef16ec6adeaf7c01c2fd0c4cc97d3860907cfa4a3b36d0c05",
      [121] = "0ae7a79758a9ffbd1c04aa080bfa82daf9641f9c2a1cc82b628cbe4006bd47701c78e5022d2ca5ca5384d26d93fb16d595b9775dab17c88ef38e4ce9fdac4b52",
      [122] = "139de16e90ad012e39f72279140f4f6b12bb93f1cbcffbd1b132f39e7f92822d2b56beafc9ed83a0bf59c5525ffd125b83294b65f51f6e8ebbf85eb1aba85b87",
      [123] = "ccd869ee70892a0f5f3c269b9e21ffc99703855c1c652774febbaf1311bd58c80fb66bc3f747dd98b2f11ad9f5d8311b7ca706d456fc82ccd46bfb01f19e8d87",
      [124] = "77469b56910b022f45f509dcfca04494d8e7978073debf96398cb5a86f31bbe55f2a807a3271b8fe124171416917ab01a87acc7bf005977caaf7b484d87d6a93",
      [125] = "577a80f7cb393ac140af066b524166bb02a8059980b65fd100ecdcbec7721d2d0519a151ae730d4b6d9b97a8e5d2415aa8157856aeae4a7444171ef2a9db252b",
      [126] = "9986e67bf52a755f8924f28dae9627f889a45d466ce8616c4ed68ec3afd7a3a14785c335c6c68d62e7379af762b2bc17117a902083a99fae337a268a5d4f4427",
      [127] = "828613968b501dc00a97e08c73b118aa8876c26b8aac93df128502ab360f91bab50a51e088769a5c1eff4782ace147dce3642554199876374291f5d921629502",
      [128] = "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321",
      [129] = "4f681e0bd53cda4b5a2041cc8a06f2eabde44fb16c951fbd5b87702f07aeab611565b19c47fde30587177ebb852e3971bbd8d3fd30da18d71037dfbd98420429",
      [130] = "b2fc6acdce83feb0b9439433915fe5dc1c73af6f17e962d7badd7ad5dd7c5032bc1744855d0ba09da5e4ab1bb1caca3aad8e4a947faa19c4769e128bacfe6b85",
      [131] = "da776a6dc98efb67553dd7867916c5782feba6e8961c878a28cc77fa99620e8417d8ca97941ae9d22bb2949c962221de98e90a18437eaeab66d00eba55d92df9",
      [132] = "d3af4d87de1febdf1b0fdf9012de0788109c2b692a59a3571bddc35b859d7d6cf5aa8aa66f1834a24d3ffed0705aa3e653a978eeb0289f8bab9e5a1aa3533121",
      [133] = "5a3c0664bc599be7686301de9d200c927eef12cb0daace1a8b540b63e3d7e0a1591aac7f87699b31bb1af24410d7ab18d0b258bc399256c25e213466e6d18420",
      [134] = "dd5ff1c06a5c050e778a691568814b4db5f09682b40636ea9e13c0552a513e49241934f1027b774b81e8aba4cced4f55c2124eb1dccae7e5c9fb09d9c7206a3e",
      [135] = "018305457c1804285649e77d1ada038a4db3b166a39dc93504584bbb9f95be2d5a2147798aa71d0f240f442d2daf4928695548cf828c7fe314149544b442fb7c",
      [136] = "389860167dc973108096b0c37276b4d62dd707c9826651318ad560af1daf234376f49e95419d310e9c5095d439f6d16e978e848d1951b1586dec6e0aaa84e61c",
      [137] = "1d91d9f1934334408937ab161416f6276975c50cc980c6fdd332496c5c0ec29f62baac0b2c0acbf8e57336acf93c1e3172eb6c627a02679b419a90acc7c8a65f",
      [138] = "a93449912b83c925b3b66af530994a565164870d4d1c779c97392d6438337d5807e5f366ce4ba5e9ea16ceb490b8bb3eb001bf4f513a463e0f01e56e2ff8a3ed",
      [139] = "884040104d933d47e61bff06f458db489f43a823baa14f3e54bc04e9a8edbb38c36a1e81f122a9dd727efcfa9f9dcb70f765c9b70f215e6b63103b4ef830444c",
      [140] = "bb1d3fa26d5432447589030b9fb510b306120ec3e50752c4c298e3ab8952523826e10f48344a10dc07e67718c0746032217ad982acc6c4f2b120f529142dcbf7",
   } do
      assert(sha512(("a"):rep(i)) == dgst)
   end

   -- negative byte values
   assert(sha512(("\255"):rep(1e3)) == "4f598854fd3db77c067dfc877450c56f326c03be82384833e01824c4b3187ac38b73fc41d6bd78e9fa8793d6106a1dc1705afb4250d2fa4508ca7b102bdb62d2")

end


local function test_md5()

   local md5 = sha.md5

   assert(md5"" == "d41d8cd98f00b204e9800998ecf8427e")
   assert(md5"a" == "0cc175b9c0f1b6a831c399e269772661")
   assert(md5"abc" == "900150983cd24fb0d6963f7d28e17f72")
   assert(md5"message digest" == "f96b697d7cb7938d525a2f31aaf161d0")
   assert(md5"abcdefghijklmnopqrstuvwxyz" == "c3fcd3d76192e4007dfb496cca67e13b")
   assert(md5"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" == "8215ef0796a20bcaaae116d3876c664a")
   assert(md5"The quick brown fox jumps over the lazy dog" == "9e107d9d372bb6826bd81d3542a419d6")
   assert(md5"The quick brown fox jumps over the lazy dog." == "e4d909c290d0fb1ca068ffaddf22cbd0")
   assert(md5"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" == "d174ab98d277d9f5a5611c2c9f419d9f")
   assert(md5(("1234567890"):rep(8)) == "57edf4a22be3c955ac49da2e2107b67a")
   assert(md5(("\255"):rep(54)) == "30855eb73c2f88ffc3005b998ca4cd69")
   assert(md5(("\255"):rep(55)) == "fd696aa639acaba9ce0e0964028fbe81")
   assert(md5(("\255"):rep(56)) == "74444b7e7b01632f3277365c8ca35ec2")

end


local function test_sha1()

   local sha1 = sha.sha1

   assert(sha1"" == "da39a3ee5e6b4b0d3255bfef95601890afd80709")
   assert(sha1"abc" == "a9993e364706816aba3e25717850c26c9cd0d89d")
   assert(sha1"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" == "84983e441c3bd26ebaae4aa1f95129e5e54670f1")
   assert(sha1"The quick brown fox jumps over the lazy dog" == "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")
   assert(sha1"The quick brown fox jumps over the lazy cog" == "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3")

end


local function test_sha3()

   assert(sha.sha3_224"" == "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7")
   assert(sha.sha3_256"" == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
   assert(sha.sha3_384"" == "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004")
   assert(sha.sha3_512"" == "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26")
   assert(sha.sha3_224"The quick brown fox jumps over the lazy dog" == "d15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795")
   assert(sha.sha3_256"The quick brown fox jumps over the lazy dog" == "69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04")
   assert(sha.sha3_384"The quick brown fox jumps over the lazy dog" == "7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41")
   assert(sha.sha3_512"The quick brown fox jumps over the lazy dog" == "01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450")
   assert(sha.shake256(64, "") == "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be")
   assert(sha.shake256(25, ("€"):rep(45))  == "8f571c3d042d43f9072941f81862e34b7127cae59edc8092e7")      -- input data is 1 byte less than block size
   assert(sha.shake256(26, ("€"):rep(90))  == "ea57f4ed3404c1a2a3f19d706cbc0971665104b49f8aea5569a2")    -- input data is 2 bytes less than two blocks
   assert(sha.shake256(27, ("€"):rep(136)) == "8c1fe6c7831770ee3c5738f2ebfddff126e71e798daf26c0735a2f")  -- input data is exactly three blocks
   assert(sha.shake256(150, "The quick brown fox jumps over the lazy dog") == "2f671343d9b2e1604dc9dcf0753e5fe15c7c64a0d283cbbf722d411a0e36f6ca1d01d1369a23539cd80f7c054b6e5daf9c962cad5b8ed5bd11998b40d5734442bed798f6e5c915bd8bb07e0188d0a55c1290074f1c287af06352299184492cbdec9acba737ee292e5adaa445547355e72a03a3bac3aac770fe5d6b66600ff15d37d5b4789994ea2aeb097f550aa5e88e4d8ff0ba07b8")
   assert(sha.shake128(32, "") == "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
   assert(sha.shake128(32, "The quick brown fox jumps over the lazy dof") == "853f4538be0db9621a6cea659a06c1107b1f83f02b13d18297bd39d7411cf10c")
   assert(sha.shake128(32, "The quick brown fox jumps over the lazy dog") == "f4202e3c5852f9182a0430fd8144f0a74b95e7417ecae17db0f8cfeed0e3e66e")
   assert(sha.shake128(12, "The quick brown fox jumps over the lazy dog") == "f4202e3c5852f9182a0430fd")
   assert(sha.shake128(11, "The quick brown fox jumps over the lazy dog") == "f4202e3c5852f9182a0430")
   assert(sha.shake128(0,  "The quick brown fox jumps over the lazy dog") == "")

   -- digest_size_in_bytes == (-1) means "generate infinite SHAKE-stream instead of fixed-width digest"
   local get_next_part_of_digest = sha.shake128(-1, "The quick brown fox jumps over the lazy dog")
   assert(get_next_part_of_digest(5) == "f4202e3c58") -- 5 bytes in hexadecimal representation
   assert(get_next_part_of_digest()  == "52")         -- size=1 is assumed when omitted
   assert(get_next_part_of_digest(0) == "")           -- size=0 is a valid size
   assert(get_next_part_of_digest(4) == "f9182a04")   -- and so on to the infinity...

   -- take long message (in chunk-by-chunk mode) and generate infinite SHAKE-stream
   local append_input_message = sha.shake128(-1)
   append_input_message("The quick brown fox")
   append_input_message(" jumps over")
   append_input_message(" the lazy dog")
   local get_next_part_of_digest = append_input_message()  -- input stream is terminated, now starting to receive the output stream
   assert(get_next_part_of_digest(5) == "f4202e3c58")      -- 5 bytes in hexadecimal representation
   assert(get_next_part_of_digest(5) == "52f9182a04")      -- and so on to the infinity...

end


local function test_blake2()

   -- Test BLAKE2b
   assert(sha.blake2b_384("") == "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100")
   assert(sha.blake2b_512("") == "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")
   assert(sha.blake2b("The quick brown fox jumps over the lazy dog") == "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918")
   assert(sha.blake2b("The quick brown fox jumps over the lazy dof") == "ab6b007747d8068c02e25a6008db8a77c218d94f3b40d2291a7dc8a62090a744c082ea27af01521a102e42f480a31e9844053f456b4b41e8aa78bbe5c12957bb")
   assert(sha.blake2b("message") == "7bd9044c67faf33ba5cd8ae162680cd9d7a8d3180b15b39952737b8572dfced52b559acd6aa7f8c833a1b3172bd2771683c793c772d4abe3dd9bd9f63c204701")
   assert(sha.blake2b("message", "key") == "550d438c7cd4e1861c529cf87c953e28370a62b11df72caf642bdd4b9fbef7997fdfe5db511d51c331260799fc68d4ce15ebe934498a494af9e77d4c88fb3efd")
   assert(sha.blake2b("message", nil, "salt") == "416397711dc3785cb45f41678647ba9e3494f6cfaa4f92c3de7bf846fc389ee966daa972c6e0b441f4dd49ada1a52988dd24359fffcbb3469e29b29298a51ab8")
   assert(sha.blake2b("message", "key", "salt") == "478c73516862923a4780520ac2236d38db45e26832e3f1a2440dddfeea3aea04ddbd0f2b3e48c680961f1d22e2c4428114d14f8afbd9bc3fc173b5507f1cab1f")
   assert(sha.blake2b(("€"):rep(100)) == "f43189d7a60c822551415b8340c40cb6606581cb66bc48a9be4108fe7d8a4bbdefd7e5c72fe1526d8170ad068cb15b578348f01a8972020cb5c1207a23d6e134")
   assert(sha.blake2b(("€"):rep(100), "100 euro") == "fcb4e39c94cc0a336570b6d0594c9d8110e598ada639705af8a6f5089dcb90a91846c6b0b4755fe86b6242c604a09c61f72590a2664a98e226748516d757f014")
   do
      local s = "my salt"           assert(#s <= 16)  -- "Salt" field
      local p = "my personalizati"  assert(#p <= 16)  -- "Personalization" field
      local salt = s..("\0"):rep(16-#s)..p            -- concatenation of "Salt" + "Personalization" fields
      assert(sha.blake2b("my message", "my key", salt) == "9268e178f82c0980033ba4e6f7056612f2c37b8244601363cfa8f8ff959bab4e790fcb47afa0bd1142f69e9d61e4babd62b291eba57c521ae6d349b11b48a2e0")
   end
   assert(sha.blake2b(("\255"):rep(999), ("\255"):rep(64), ("\255"):rep(32)) == "0d8a6a5cf6e59853213d760fbc5cb66313e1d5182aecf9dc9eafe04f96e7888f0222940a57f937b353068f2a571e778769c6a840635738a86d234925cbd11e42")
   assert(sha.blake2b(("\128"):rep(17), ("\128"):rep(17), ("\128"):rep(17)) == "47a679b056586be8f60346749e996c8c6e83ae8fc7e89a71fb0954c8e3a4b326d157082457390468b82ff048231c8ef5a8cd4ad0929800dcfd2e344f19409d26")
   assert(sha.blake2b(("\128"):rep(9), ("\128"):rep(9), ("\128"):rep(9)) == "9739afd1184492ca2ac8e223d050981258d5739627762cbd64f06f5b0cb827522d13ee1b229f2ab660b554e59a6e25bea5c4a3633cf4703dcf998e5f211f48b4")
   assert(sha.blake2b("your message", "your key") == "feee3e3aac7d5a3a4653fb70667ad6fb5fafe5256c78867b421eb0ce4134fc62784002b261056c4ef4222e99a8944826dff6f4845ac0117df128de116b159d75")
   local append = sha.blake2b(nil, "your key")
   append("your")
   append(" message")
   assert(append() == "feee3e3aac7d5a3a4653fb70667ad6fb5fafe5256c78867b421eb0ce4134fc62784002b261056c4ef4222e99a8944826dff6f4845ac0117df128de116b159d75")

   -- Test BLAKE2s
   assert(sha.blake2s_224("") == "1fa1291e65248b37b3433475b2a0dd63d54a11ecc4e3e034e7bc1ef4")
   assert(sha.blake2s_256("") == "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
   assert(sha.blake2s("message") == "e6d7039c6d8c2ae1706e2cd3d2684e59d8b86ea9d21273a1e06263932ea367a4")
   assert(sha.blake2s("message", "key") == "6167e07bf13af66076d94c1f6e395ee73b647d4c7013238d63808e805ae3ae59")
   assert(sha.blake2s("message", nil, "salt") == "21faaaeeaa27906aa5465510b6640cb383d536ef6a1ef9e2b91fc4beccb1dcd0")
   assert(sha.blake2s("message", "key", "salt") == "9953f155c11cb98eb4a62db577dc2ff6ff6c1a7b36c2b5ad3274f202bea23d67")
   assert(sha.blake2s(("€"):rep(100)) == "d58876a6350bb985155de324df9239fa241b3bc80517d88282f19aaf77701eba")
   assert(sha.blake2s(("€"):rep(100), "100 euro") == "9e54259e2ff40c09dbbed369e4c5a01a150ec01e31cb0565a2a445dcf9bf279d")
   do
      local s = "my salt"   assert(#s <= 8)  -- "Salt" field
      local p = "my pers"   assert(#p <= 8)  -- "Personalization" field
      local salt = s..("\0"):rep(8-#s)..p    -- concatenation of "Salt" + "Personalization" fields
      assert(sha.blake2s("my message", "my key", salt) == "96d9b162046d282b81a651dcd5d49df05f67f6617bb56ad28cad22a7c1040bc8")
   end
   assert(sha.blake2s(("\255"):rep(999), ("\255"):rep(32), ("\255"):rep(16)) == "2502074ea85b4eb732c4296c82c662371ed80ca962920e0b6169030bf4633228")

   -- Test BLAKE2bp
   assert(sha.blake2bp("message") == "9cf494d3adfa1c639280b7e2101de182014fc142aec93d5a31c54c608158335e993a8955bf6f062e0669cad9ebdcdd0144da168460745528cb2a49c9528256a3")
   assert(sha.blake2bp("message", "key") == "aeb49f2817db0ef5910fec836272de7be819a6017920dd6d94d9380b16f24d5d5c930adc6d147cc12dae984fbbc0379c4a333c98a28f2beb942752dca49838c5")
   assert(sha.blake2bp("message", nil, "salt") == "b093b4ee84640dfe06a5eb21a0411b788d675c91b898a9efb5da4f819c54d2135a1d939af1f4b3b2fefea53cfa1ed77d2ef102ed19a65118593161a058e27a9f")
   assert(sha.blake2bp("message", "key", "salt") == "bf71085230daaffdfadd3e2d745f733c3a7000a507a681b46198697f43cba7ae0c9f17b1231434a445f46734b5e21d51223d4760886a5fb5784a181d85f9bc53")

   -- Test BLAKE2sp
   assert(sha.blake2sp("message") == "c278b6c68e2ecfa36434c65acfec9076d797a1449d104ac454df200b8a429a96")
   assert(sha.blake2sp("message", "key") == "09fd315f5347107d9b94de22f2abe2f358d029c0294c2b577f285c7b0c01d1db")
   assert(sha.blake2sp("message", nil, "salt") == "5a93b13e04ac708d0bf1a1f855f32ff6eb8f9716a36cd18d5f1a5cdc89c8656e")
   assert(sha.blake2sp("message", "key", "salt") == "d2b13f23784e5904967d0a94913523c9657b3e4c57c858217bf0074afbf895d3")
   -- Want more test vectors for BLAKE2sp? You can get BLAKE2sp hash sum (no key, no salt) of any file using 7-Zip or RAR:
   --    7-Zip (version 15.06+):
   --       7z h -scrcblake2sp YOUR_FILE
   --    RAR (version 5.0+):
   --       rar a -m0 -ma -htb -inul tmp.rar YOUR_FILE && rar lt tmp.rar && rm tmp.rar
   --       (for Windows users: replace "rm" with "del")

   -- Test BLAKE2Xb
   assert(sha.blake2xb(65, "message") == "90aa97980b876527d78da8639d91419b76a6cb93aa2bccf7ef69603c3b37a9c7c708662540400c523e304a7f50a65d64eb0d16a295d2e33a97455e958c73efc2c7")
   assert(sha.blake2xb(65, "message", "key") == "2fcf18805eec564af2e24c5493b9038b1f652900b413b85d5f1b92ee4f281792ff2592657d915c4800d3ca026a47c4ec3692134a28a1f8d6cc310708bdfb501e46")
   assert(sha.blake2xb(65, "message", nil, "salt") == "2885f976dd6eeb7253d0cd3dce63a5d8ab480d3288ef193b7bad722fe914f382ab3b929709f9370290222d06e133e047a6d8d8f09d46fa0f0961bedb3f55d74be5")
   assert(sha.blake2xb(65, "message", "key", "salt") == "088dfd13d5cbab9505ae2e0d281bc1ca95dd74c0a00c021e1ffe63532a88ce43578fac63d99a596460af0d52ccbba21d2d7667384f3feff82a0507e4fc1180a6de")
   local get_next_part_of_digest = sha.blake2xb(-16 * 2^20, "The quick brown fox jumps over the lazy dog")
   assert(get_next_part_of_digest(5) == "53e2dcdfe2")
   assert(get_next_part_of_digest()  == "1b")
   assert(get_next_part_of_digest(0) == "")
   assert(get_next_part_of_digest(3) == "21af5b")
   get_next_part_of_digest("seek", 16 * 2^20 - 5)
   assert(get_next_part_of_digest(5) == "b2b5312606")
   assert(get_next_part_of_digest(1) == "")
   get_next_part_of_digest("seek", 16 * 2^20 - 5)
   assert(get_next_part_of_digest(555) == "b2b5312606")
   get_next_part_of_digest("seek", -10)
   assert(get_next_part_of_digest(15) == "53e2dcdfe2")
   local append_input_message = sha.blake2xb(-16 * 2^20)
   append_input_message("The quick brown fox")
   append_input_message(" jumps over the lazy dog")
   local get_next_part_of_digest = append_input_message()
   assert(get_next_part_of_digest(4) == "53e2dcdf")
   assert(get_next_part_of_digest(4) == "e21b21af")
   local get_next_part_of_digest = sha.blake2xb(-1, "The quick brown fox jumps over the lazy dog")
   assert(get_next_part_of_digest(5) == "364e84ca4c")
   assert(get_next_part_of_digest(5) == "103df29230")
   get_next_part_of_digest("seek", 10*2^30)
   assert(get_next_part_of_digest(5) == "eeafce070f")
   get_next_part_of_digest("seek", 0)
   assert(get_next_part_of_digest(5.0) == "364e84ca4c")
   get_next_part_of_digest("seek", 1)
   assert(get_next_part_of_digest(5) == "4e84ca4c10")
   get_next_part_of_digest("seek", -10)
   assert(get_next_part_of_digest(20) == "5538642bb3ddedba69a4364e84ca4c103df29230")
   get_next_part_of_digest("seek", 2^31-10)
   assert(get_next_part_of_digest(20) == "e2a4267324dd36006f3a985f88b74111f494a73c")
   get_next_part_of_digest("seek", 2^32-10)
   assert(get_next_part_of_digest(20) == "d13c13778d4e4b59044c8a6126261b814814c280")
   get_next_part_of_digest("seek", 64*2^31-10)
   assert(get_next_part_of_digest(20) == "f638601af5aa9bac8b5f0ee69ee2970ff68cd3a3")
   get_next_part_of_digest("seek", 64*2^32-10)
   assert(get_next_part_of_digest(20) == "5538642bb3ddedba69a4364e84ca4c103df29230")

   -- Test BLAKE2Xs
   assert(sha.blake2xs(33, "message") == "a738fcffa5c656eebb0e7dc46fd8eafff960dcb46d36cb2896b444bfbbd623f910")
   assert(sha.blake2xs(33, "message", "key") == "a7d460f42db67f6f07d85ae346ec5dba41ca056e67a366cef583f36f9e3d969d52")
   assert(sha.blake2xs(33, "message", nil, "salt") == "8370c1b120c6ae76a5cdbf24bf8c082ed3d647127726f5da85a1c1ffd29e35335c")
   assert(sha.blake2xs(33, "message", "key", "salt") == "f5d6f28e3720d789c847b65e2f1113792e6ac4da59fa653c10f3b0a9304021d7a1")
   assert(sha.blake2xs(132, "your string") == "4fae7a4abcf47aec81991c370e8c716adc5bf7a142e932fc18b50d325f5ca7059fe7369fb86088b253dcbec9ff9fd168d5a229e507c9d984e9e8c0e1fa27824b51de5af9323594f0decd317ad3ed54aac7e5f816728fb39f7c3df873479f9063188566b788150a0dfaded9f06cf45aa1ef1bb80451e8f4dc8554ae790797188dce0e13fa")
   local get_next_part_of_digest = sha.blake2xs(-1, "The quick brown fox jumps over the lazy dog")
   assert(get_next_part_of_digest(10) == "0650cde4df888a06eada")
   get_next_part_of_digest("seek", -10)
   assert(get_next_part_of_digest(20) == "d2b24a4e7e4d924cfbe30650cde4df888a06eada")
   get_next_part_of_digest("seek", 2^31-10)
   assert(get_next_part_of_digest(20) == "c635d7a48f65efe8c65e65e076f41ad64504f6d1")
   get_next_part_of_digest("seek", 2^32-10)
   assert(get_next_part_of_digest(20) == "f9c9378e8778ce71d78e77c378116835376b1c46")
   get_next_part_of_digest("seek", 32*2^31-10)
   assert(get_next_part_of_digest(20) == "1ba18817e49f0319f7ef07da100f3419bc4db148")
   get_next_part_of_digest("seek", 32*2^32-10)
   assert(get_next_part_of_digest(20) == "d2b24a4e7e4d924cfbe30650cde4df888a06eada")

end


local function test_hmac()

   local hmac = sha.hmac

   assert(hmac(sha.sha1,   "your key", "your message") == "317d0dfd868a5c06c9444ac1328aa3e2bfd29fb2")
   assert(hmac(sha.sha512, "your key", "your message") == "2f5ddcdbd062a5392f07b0cd0262bf52c21bfb3db513296240cca8d5accc09d18d96be0a94995be4494c032f1eda946ad549fb61ccbe985d160f0b2f9588d34b")
   assert(hmac(sha.md5,    "", "") == "74e6f7298a9c2d168935f58c001bad88")
   assert(hmac(sha.sha256, "", "") == "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad")
   assert(hmac(sha.sha1,   "", "") == "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d")
   assert(hmac(sha.md5,    "key", "The quick brown fox jumps over the lazy dog") == "80070713463e7749b90c2dc24911e275")
   assert(hmac(sha.sha256, "key", "The quick brown fox jumps over the lazy dog") == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
   assert(hmac(sha.sha1,   "key", "The quick brown fox jumps over the lazy dog") == "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")

   -- chunk-by-chunk mode
   local append = hmac(sha.sha1, "key")
   append("The quick brown fox")
   append("")  -- empty string is allowed as a valid chunk
   append(" jumps over the lazy dog")
   assert(append() == "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")  -- invocation without an argument receives the result

   local key, message = ("\170"):rep(131), "Test Using Larger Than Block-Size Key - Hash Key First"
   assert(hmac(sha.sha3_224, key, message) == "b4a1f04c00287a9b7f6075b313d279b833bc8f75124352d05fb9995f")
   assert(hmac(sha.sha3_256, key, message) == "ed73a374b96c005235f948032f09674a58c0ce555cfc1f223b02356560312c3b")
   assert(hmac(sha.sha3_384, key, message) == "0fc19513bf6bd878037016706a0e57bc528139836b9a42c3d419e498e0e1fb9616fd669138d33a1105e07c72b6953bcc")
   assert(hmac(sha.sha3_512, key, message) == "00f751a9e50695b090ed6911a4b65524951cdc15a73a5d58bb55215ea2cd839ac79d2b44a39bafab27e83fde9e11f6340b11d991b1b91bf2eee7fc872426c3a4")

   assert(not pcall(hmac, function(x) return sha.sha256(x) end, "key", "message"))  -- must raise "unknown hash function" error

end


local function test_base64()

   local bin_to_base64 = sha.bin2base64
   assert(bin_to_base64""       == ""        )
   assert(bin_to_base64"f"      == "Zg=="    )
   assert(bin_to_base64"fo"     == "Zm8="    )
   assert(bin_to_base64"foo"    == "Zm9v"    )
   assert(bin_to_base64"foob"   == "Zm9vYg==")
   assert(bin_to_base64"fooba"  == "Zm9vYmE=")
   assert(bin_to_base64"foobar" == "Zm9vYmFy")

   local base64_to_bin = sha.base642bin
   assert(base64_to_bin""         == ""      )
   assert(base64_to_bin"Zg=="     == "f"     )
   assert(base64_to_bin"Zm8="     == "fo"    )
   assert(base64_to_bin"Zm9v"     == "foo"   )
   assert(base64_to_bin"Zm9vYg==" == "foob"  )
   assert(base64_to_bin"Zm9vYmE=" == "fooba" )
   assert(base64_to_bin"Zm9vYmFy" == "foobar")

end



local function test_all()

   test_md5()

   test_sha1()

   test_sha256()

   assert(sha.sha224"abc" == "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
   assert(sha.sha224"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" == "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525")

   test_sha512()

   assert(sha.sha384"abc" == "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
   assert(sha.sha384"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" == "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039")

   assert(sha.sha512_224"abc" == "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa")
   assert(sha.sha512_224"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" == "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9")

   assert(sha.sha512_256"abc" == "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23")
   assert(sha.sha512_256"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" == "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a")

   test_sha3()

   test_blake2()

   test_hmac()

   test_base64()

   print"All tests passed"

end


test_all()


--------------------------------------------------------------------------------
-- BENCHMARK
--------------------------------------------------------------------------------

local part = ("\165"):rep(2^7 * 3^2 * 13 * 17)   -- 254592 = least common multiple of all SHA functions' block lengths
local number_of_measures = 5   -- number of measures for each SHA function (set to 1 if you're in a hurry)
local measure_duration = 3.0   -- one measure would take about 3 sec (don't reduce this value)

local function to3digit(x)
   local n = math.floor(math.log(2*x)/math.log(10))
   x = x / 10^n
   -- Now: x in the range (0.5)...(5.0)
   local four_digits = math.floor(x * 1000 + 0.5)
   return math.floor(four_digits / 1000).."."..tostring(four_digits):sub(-3).."*10^"..n
end

local function benchmark(hash_func)
   local N = 0.5
   local function measure()
      local tm = os.clock()
      local x = hash_func()
      for j = 1, N do
         x(part)
      end
      local result = x()
      return os.clock() - tm, result
   end
   local seconds_passed
   repeat
      N = N * 2
      seconds_passed = measure()
   until seconds_passed > measure_duration / 10
   local N_calc = math.max(1, math.floor(N * measure_duration / seconds_passed + 0.5))
   if N_calc ~= N then
      N, seconds_passed = N_calc
   end
   local bytes_hashed = 1.0 * #part * N
   for j = 1, number_of_measures do
      seconds_passed = seconds_passed or measure()
      local bytes_per_secods = bytes_hashed / seconds_passed
      -- print('CPU seconds to hash 1 GByte:   '..math.floor(0.5 + 2^30 / bytes_per_secods * 100) / 100)
      print('Hashing speed (Bytes per Second):   '..to3digit(bytes_per_secods))
      seconds_passed = nil
   end
end

for _, fn in ipairs{"md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512", "blake2s", "blake2b"} do
   print()
   print(fn:gsub("_", "-"):upper())
   benchmark(sha[fn])
end
