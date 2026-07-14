import type { EncryptionAlgorithm } from "../../algorithms.js"

const BLOCK_SIZE = 8
const S_BOX_SIZE = 256

// RFC 2144 Appendix A defines eight 256-word substitution boxes.
const S_BOX_HEX = [
    "30fb40d49fa0ff0b6beccd2f3f258c7a1e213f2f9c004dd36003e540cf9fc949bfd4af2788bbbdb5e203409098d09675",
    "6e63a0e015c361d2c2e7661d22d4ff8e28683b6fc07fd059ff2379c8775f50e243c340d3df2f8656887ca41aa2d2bd2d",
    "a1c9e0d6346c481961b76d8722540f2f2abe32e1aa54166b22568e3aa2d341d066db40c8a784392f004dff2f2db9d2de",
    "97943fac4a97c1d8527644b7b5f437a7b82cbaefd751d1596ff7f0ed5a097a1f827b68d090ecf52e22b0c054bc8e5935",
    "4b6d2f7f50bb64a2d2664910bee5812db7332290e93b159fb48ee4114bff345dfd45c240ad31973fc4f6d02e55fc8165",
    "d5b1caada1ac2daea2d4b76dc19b0c50882240f20c6e4f38a4e4bfd74f5ba272564c1d2fc59c5319b949e354b04669fe",
    "b1b6ab8ac71358dd6385c545110f935d57538ad56a390493e63d37e02a54f6b33a787d5f6276a0b519a6fcdf7a42206a",
    "29f9d4d5f61b1891bb72275eaa50816738901091c6b505eb84c7cb8c2ad75a0f874a1427a2d1936b2ad286afaa56d291",
    "d7894360425c750d93b39e26187184c96c00b32d73e2bb14a0bebc3c5462377964459eab3f328b827718cf8259a2cea6",
    "04ee002e89fe78e63fab0950325ff6c281383f056963c5c876cb5ad6d49974c9ca180dcf380782d5c7fa5cf68ac31511",
    "35e79e1347da91d0f40f9086a7e2419e31366241051ef495aa573b044a805d8d548300d000322a3cbf64cddfba57a68e",
    "75c6372b50afd341a7c13275915a0bf56b54bfab2b0b1426ab4cc9d7449ccd82f7fbf265ab85c5f31b55db94aad4e324",
    "cfa4bd3f2deaa3e29e204d02c8bd25aceadf55b3d5bd9e98e31231b22ad5ad6c954329deadbe4528d8710f69aa51c90f",
    "aa786bf622513f1eaa51a79b2ad344cc7b5a41f0d37cfbad1b06950541ece491b4c332e6032268d4c9600accce387e6d",
    "bf6bb16c6a70fb780d03d9c9d4df39dee01063da4736f4645ad328d8b347cc9675bb0fc398511bfb4ffbcc35b58bcf6a",
    "e11f0abcbfc5fe4aa70aec10ac39570a3f04442f6188b153e0397a2e5727cb799ceb418f1cacd68d2ad37c960175cb9d",
    "c69dff09c75b65f0d9db40d8ec0e77794744ead4b11c3274dd24cb9e7e1c54bdf01144f9d2240eb19675b3fda3ac3755",
    "d47c27af51c85f4d56907596a5bb15e6580304f0ca042cf1011a37ea8dbfaadb35ba3e4a3526ffa0c37b4d09bc306ed9",
    "98a526665648f725ff5e569d0ced63d07c63b2cf700b45e1d5ea50f185a92872af1fbda7d4234870a7870bf32d3b4d79",
    "42e041980cd0ede726470db8f881814c474d6ad77c0c5e5cd1231959381b7298f5d2f4dbab8386536e2f1e2383719c9e",
    "bd91e0469a56456edc39200c20c8c571962bda1ce1e696ffb141ab087cca89b91a69e78302cc4843a2f7c579429ef47d",
    "427b169c5ac9f049dd8f0f005c8165bf1f201094ef0ba75b69e3cf7e393f4380fe61cf7aeec5207a55889c9472fc0651",
    "ada7ef794e1d7235d55a63cede0436ba99c430ef5f0c079418dcdb7da1d6eff3a0b52f7b59e83605ee15b094e9ffd909",
    "dc440086ef944459ba83ccb3e0c3cdfbd1da41813b092ab1f997f1c1a5e6cf7b01420ddbe4e7ef5b25a1ff41e180f806",
    "1fc41080179bee7ad37ac6a9fe5830a498de8b7f77e83f4e7992926924fa9f7be113c85bacc40083d7503525f7ea615f",
    "621431540d554b635d681121c866c3593d63cf73cee234c0d4d87e875c672b21071f618139f7627f361e3084e4eb573b",
    "602f64a4d63acd9c1bbc46359e81032d2701f50c99847ab4a0e3df79ba6cf38c108430942537a95ef46f6ffea1ff3b1f",
    "208cfb6a8f458c74d9e0a2274ec73a34fc884f693e4de8dfef0e00883559648d8a45388c1d804366721d9bfda58684bb",
    "e8256333844e8212128d8098fed33fb4ce280ae127e19ba5d5a6c252e49754bdc5d655ddeb66706477840b4da1b6a801",
    "84db26a9e0b5671421f043b7e5d0586054f03084066ff472a31aa153dadc4755b5625dbf68561be683ca6b942d6ed23b",
    "eccf01dba6d3d0bab6803d5caf77a70933b4a34c397bc8d65ee22b955f0e530481ed6f6120e74364b45e1378de18639b",
    "881ca122b96726d18049a7e822b7da7b5e552d255272d23779d2951cc60d894c488cb4021ba4fe5ba4b09f6b1ca815cf",
    "a20c30058871df63b9de2fcb0cc6c9e90beeff53e3214517b45428359f63293cee41e7296e1d2d7c500452861e6685f3",
    "f33401c630a22c9531a7085060930f1373f98417a1269859ec645c4452c877a9cdff33a6a02b17417cbad9a22180036f",
    "50d99c08cb3f4861c26bd76564a3f6ab8034267625a75e7be4e6d1fc20c710e6cdf0b68017844d3b31eef84d7e0824e4",
    "2ccb49eb846a3bae8ff77888ee5d60f67af756732fdd5cdba11631c130f66f43b3faec54157fd7faef8579ccd152de58",
    "db2ffd5e8f32ce19306af97a02f03ef899319ad5c242fa0fa7e3ebb0c68e4906b8da230c80823028dcdef3c8d35fb171",
    "088a1bc8bec0c56061a3c9e8bca8f54dc72feffa22822e9982c570b4d8d94e898b1c34bc301e16e6273be979b0ffeaa6",
    "61d9b8c600b24869b7ffce3f08dc283b43daf65af7e197987619b72f8f1c9ba4dc8637a016a7d3b19fc393b7a7136eeb",
    "c6bcc63e1a513742ef6828bc520365d62d6a77ab3527ed4b821fd216095c6e2edb92f2fb5eea29cb145892f591584f7f",
    "5483697b2667a8cc851960488c4bacea833860d40d23e0f96c387e8a0ae6d249b284600cd835731ddcb1c647ac4c56ea",
    "3ebd81b3230eabb06438bc87f0b5b1fa8f5ea2b3fc1846420a036b7a4fb089bd649da589a345415e5c0383233e5d3bb9",
    "43d795727e6dd07c06dfdf1e6c6cc4ef7160a53973bfbe70838776054523ecf18defc24025fa5d9feb903dbfe810c907",
    "47607fff369fe44b8c1fc644aececa90beb1f9bfeefbcaeae8cf195051df07ae920e8806f0ad0548e13c8d83927010d5",
    "11107d9f07647db9b2e3e4d43d4f285eb9afa820fade82e0a067268b8272792e553fb2c0489ae22bd4ef9794125e3fbc",
    "21fffcee825b1bfd9255c5ed1257a2404e1a8302bae07fff528246e78e57140e3373f7bf8c9f8188a6fc4ee8c982b5a5",
    "a8c01db7579fc26467094f31f2bd3f5f40fff7c11fb78dfc8e6bd2c1437be59b99b03dbfb5dbc64b638dc0e655819d99",
    "a197c81c4a012d6ec5884a28ccc36f71b843c2136c0743f18309893c0feddd5f2f7fe850d7c07f7e02507fbf5afb9a04",
    "a747d2d01651192eaf70bf3e58c313805f98302e727cc3c40a0fb4020f7fef828c96fdad5d2c2aae8ee99a4950da88b8",
    "8427f4a01eac5790796fb4498252dc15efbd7d9ba672597dada840d845f54504fa5d7403e83ec3054f91751a925669c2",
    "23efe941a903f12e60270df20276e4b694fd6574927985b28276dbcb02778176f8af918d4e48f79e8f616ddfe29d840e",
    "842f7d83340ce5c896bbb68293b4b148ef303cab984faf28779faf9b92dc560d224d1e208437aa887d29dc962756d3dc",
    "8b907ceeb51fd240e7c07ce3e566b4a1c3e9615e3cf8209d6094d1e3cd9ca3415c76460e00ea983bd4d67881fd47572c",
    "f76cedd9bda8229c127dadaa438a074e1f97c090081bdb8a93a07ebeb938ca1597b03cff3dc2c0f88d1ab2ec64380e51",
    "68cc7bfbd90f2788124901815de5ffd4dd7ef86a76a2e214b9a40368925d958f4b39fffaba39aee9a4ffd30bfaf7933b",
    "6d498623193cbcfa27627545825cf47a61bd8ba0d11e42d1cead04f4127ea39210428db78272a9729270c4a8127de50b",
    "285ba1c83c62f44f35c0eaa5e805d231428929fbb4fcdf824fb66a530e7dc15b1f081fab108618aefcfd086df9ff2889",
    "694bcc11236a5cae12deca4d2c3f8cc5d2d02dfef8ef5896e4cf52da95155b67494a488cb9b6a80c5c8f82bc89d36b45",
    "3a609437ec00c9a9447152530a874b49d773bc407c34671c02717ef64feb5536a2d02fffd2bf60c4d43f03c050b4ef6d",
    "07478cd1006e1888a2e53f55b9e6d4bca204801697573833d7207d67de0f8f3d72f87b33abcc4f337688c55d7b00a6b0",
    "947b0001570075d2f9bb88f88942019e4264a5ff856302e072dbd92bee971b696ea22fde5f08ae2baf7a616de5c98767",
    "cf1febd261efc8c2f1ac2571cc8239c267214cb8b1e583d1b7dc3e627f10bdcef90a5c380ff0443d606e6dc660543a49",
    "5727c1482be98a1d8ab4173820e1be24af96da0f6845842599833be5600d457d282f93508334b362d91d11202b6d8da0",
    "642b1e319c305a0052bce6881b03588af7baefd54142ed9ca4315c1183323ec5dfef4636a133c501e9d3531cee353783",
    "9db304201fb6e9dea7be7befd273a2984a4f7bdb64ad8c5785510443fa020ed17e287affe60fb663095f35a179ebf120",
    "fd059d436497b7b1f3641f63241e4adf28147f5f4fa2b8cdc94300400cc32220fdd30b30c0a5374f1d2d00d924147b15",
    "ee4d111a0fca516771ff904c2d195ffe1a05645f0c13fefe081b08ca0517012180530100e83e5efeac9af4f87fe72701",
    "d2b8ee5f06df4261bb9e9b8a7293ea25ce84ffdff57188013dd64b04a26f263b7ed48400547eebe6446d4ca06cf3d6f5",
    "2649abdfaea0c7f536338cc1503f7e93d377206111b638e172500e03f80eb2bbabe0502eec8d77de57971e81e14f6746",
    "c93354006920318f081dbb99ffc304a54d3518057f3d5ce3a6c866c65d5bcca9daec6fea9f926f919f46222f3991467d",
    "a5bf6d8e1143c44f43958302d0214eeb022083b83fb6180c18f8931e281658e626486e3e8bd78a707477e4c1b506e07c",
    "f32d0a2579098b02e4eabb8128123b2369dead381574ca16df871b62211c40b7a51a9ef90014377b041e8ac809114003",
    "bd59e4d2e3d156d54fe876d52f91a340557be8de00eae4a70ce5c2ec4db4bba6e756bdffdd3369acec17b03506572327",
    "99afc8b056c8c3916b65811c5e1461196e85cb75be07c002c2325577893ff4ec5bbfc92dd0ec3b25b7801ab78d6d3b24",
    "20c763efc366a5fc9c3828800ace3205aac9548aeca1d7c7041afa321d16625a6701902c9b757a5431d477f79126b031",
    "36cc6fdbc70b8b46d9e66a4856e55a79026a4ceb52437eff2f8f76b40df980a58674cde3edda04eb17a9be042c18f4df",
    "b7747f9dab2af7b4efc34d202e096b7c1741a254e5b6a035213d42f62c1c7c2661c2f50f6552daf9d2c231f825130f69",
    "d8167fa20418f2c8001a96a60d1526ab63315c215e0a72ec49bafefd187908d98d0dbd86311170a73e9b640ccc3e10d7",
    "d5cad3b60caec388f73001e16c728aff71eae2a11f9af36ecfcbd12fc1de8417ac07be6bcb44a1d88b9b0f56013988c3",
    "b1c52fcab4be31cdd878280612a3a4e26f7de53258fd7eb6d01ee90024adffc2f4990fc59711aac5001d7b9582e5e7d2",
    "109873f600613096c32d9521ada121ff299084157fbb977faf9eb3db29c9ed2a5ce2a465a730f32cd0aa3fe88a5cc091",
    "d49e2ce70ce454a9d60acd86015f191977079103dea03af678a8565edee356df21f05cbe8b75e387b3c50651b8a5c3ef",
    "d8eeb6d2e523be77c21545292f69efdfafe67afbf470c4b2f3e0eb5bd6cc987639e4460c1fda85381987832fca007367",
    "a99144f8296b299e492fc2959266beabb5676e699bd3dddadf7e052fdb25701c1b5e51eef65324e66afce36c0316cc04",
    "8644213eb7dc59d07965291fccd6fd4341823979932bcdf6b657c34d4edfd2827ae5290c3cb9536b851e20fe9833557e",
    "13ecf0b0d3ffb3723f85c5c10aef7ed27ec90c042c6e74b99b0e66dfa6337911b86a7fff1dd358f544dd9d441731167f",
    "08fbf1fae7f511ccd2051b00735aba002ab722d8386381cbacf6243a69befd7ae6a2e77ff0c720cdc4494816ccf5c180",
    "3885164015b0a848e68b18cb4caadeff5f480a010412b2aa259814fc41d0efe24e40b48d248eb6fb8dba1cfe41a99b02",
    "1a550a04ba8f65cb7251f4e795a51725c106ecd797a5980ac539b9aa4d79fe6af2f3f76368af8040ed0c9e5611b4958b",
    "e1eb5a888709e6b0d7e071564e29fea76366e52d02d1c000c4ac8e059377f5710c05372a578535f22261be02d642a0c9",
    "df13a28074b55bd2682199c0d421e5ec53fb3ce8c8adedb328a87fc93d9599815c1ff900fe38d3990c4eff0b062407ea",
    "aa2f4fb14fb9697690c79505b0a8a774ef55a1ffe59ca2c2a6b62d27e66a4263df65001f0ec50966dfdd55bc29de0655",
    "911e739a17af897532c7911c89f894680d01e980524755f403b63cc90cc844b2bcf3f0aa87ac36e9e53a742601b3d82b",
    "1a9e744964ee2d7ecddbb1da01c94910b868bf800d26f3fd9342ede704a5c284636737b650f5b616f24766e38eca36c1",
    "136e05dbfef18391fb887a37d6e7f7d4c7fb7dc93063fcdfb6f589deec2941da26e46695b7566419f654efc5d08d58b7",
    "48925401c1bacb7fe5ff550fb60830495bb5d0e887d72e5aab6a6ee1223a66cec62bf3cd9e0885f968cb3e47086c010f",
    "a21de820d18b69def3f65777fa02c3f6407edac3cbb3d5501793084db0d70eba0ab378d5d951fb0cded7da564124bbe4",
    "94ca0b560f5755d1e0e1e56e6184b5be580a249f94f74bc0e327888e9f7b5561c3dc028005687715646c6bd744904db3",
    "66b4f0a3c0f1648a697ed5af49e92ff6309e374f2cb6356a858085734991f84076f0ae02083be84d28421c9a44489406",
    "736e4cb8c10929108bc95fc67d869cf4134f616f2e77118db31b2be1aa90b4723ca5d7177d161bba9cad9010af462ba2",
    "9fe459d245d34559d9f2da13dbc65487f3e4f94e176d486f097c13ea631da5c7445f7382175683f4cdc66a9770be0288",
    "b3cdcf726e5dd2f320936079459b80a5be60e2dba9c23101eba5315c224e42f21c5c1572f6721b2c1ad2fff38c25404e",
    "324ed72f4067b7fd0523138e5ca3bc78dc0fd66e75922283784d6b1758ebb16e44094f853f481d87fcfeae7b77b5ff76",
    "8c2302bfaaf475565f46b02a2b0928013d38f5f70ca81f3652af4a8a66d5e7c0df3b0874950551101b5ad7a8f61ed5ad",
    "6cf6e47920758184d0cefa6588f7be584a0468260ff6f8f3a09c7f705346aba05ce96c28e176eda36bac307f376829d2",
    "85360fa917e3fe2a24b79767f5a96b20d6cd259568ff1ebf7555442cf19f06bef9e0659aeeb9491d34010718bb30cab8",
    "e822fe1588570983750e6249da627e555e76ffa8b15345466d47de08efe9e7d4f6fa8f9d2cac6ce14ca34867e2337f7c",
    "95db08e7016843b4eced5cbc325553acbf9f0960dfa1e2ed83f0579d63ed86b91ab6a6b8de5ebe39f38ff7328989b138",
    "33f14961c01937bdf506c6dae4625e7ea308ea994e23e33c79cbd7cc48a14367a3149619fec94bd5a114174aeaa01866",
    "a084db2d09a8486fa888614a2900af9801665991e1992863c8f30c602e78ef3cd0d51932cf0fec14f7ca07d2d0a82072",
    "fd41197e9305a6b0e86be3da74bed3cd372da53c4c7f4448dab5d4406dba0ec3083919a79fbaeed949dbcfb04e670c53",
    "5c3d9c0164bdb9412c0e636aba7dd9cdea6f7388e70bc76235f29adb5c4cdd8df0d48d8cb88153e208a198661ae2eac8",
    "284caf89aa9282239334be533b3a21bf16434be39aea3906efe8c36ef890cdd980226daec340a4a3df7e9c09a694a807",
    "5b7c5ecc221db3a69a69a02f68818a54ceb2296f53c0843afe89365525bfe68ab4628abccf222ebf25ac6f48a9a99387",
    "53bddb65e76ffbe7e967fd780ba935638e342bc1e8a11be94980740dc8087dfc8de4bf99a11101a07fd37975da5a26c0",
    "e81f994f9528cd89fd339fedb87834bf5f04456d22258698c9c4c83b2dc156be4f628daa57f55ec5e2220abed2916ebf",
    "4ec75b9524f2c3c042d15d99cd0d7fa07b6e27ffa8dc8af07345c106f41e232f35162386e6ea89263333b094157ec6f2",
    "372b74af692573e4e9a9d848f31602893a62ef1da787e238f3a5f67674364853209510634576698db6fad407592af950",
    "36f735234cfb6e877da4cec06c152daacb0396a8c50dfe5dfcd707ab0921c42f89dff0bb5fe2be78448f4f33754613c9",
    "2b05d08d48b9d585dc049441c8098f9b7dede786c39a3373424100056a0917510ef3c8a6890072d628207682a9a9f7be",
    "bf32679dd45b5b75b353fd00cbb0e358830f220a1f8fb214d372cf08cc3c4a138cf63166061c87be88c98f886062e397",
    "47cf8e7ab6c852833cc2acfb3fc069764e8f025264d8314dda3870e31e665459c10908f0513021a56c5b68b7822f8aa0",
    "3007cd3e74719eefdc872681073340d47e432fd90c5ec2418809286cf592d89108a930f6957ef305b7fbffbdc266e96f",
    "6fe4ac98b173ecc0bc60b42a953498dafba1ae122d4bd7360f25faaba4f3fcebe2969123257f0c3d9348af49361400bc",
    "e8816f4a3814f200a3f940439c7a54c2bc704f57da41e7f9c25ad33a54f4a084b17f550559357cbeedbd15c87f97c5ab",
    "ba5ac7b5b6f6deaf3a479c3a5302da25653d7e6a54268d4951a477ea5017d55bd7d25d8844136c760404a8c8b8e5a121",
    "b81a928a60ed586997c55b96eaec991b2993591301fdb7f1088e8dfa9ab6f6f53b4cbf9f4a5de3abe6051d35a0e1d855",
    "d36b4cf1f544edebb0e93524bebb8fbda2d762cf49c92f5438b5f3317128a45448392905a65b1db8851c97bdd675cf2f",
    "85e04019332bf567662dbfffcfc656932a8d7f6fab9bc912de6008a12028da1f0227bce74d64291618fac30050f18b82",
    "2cb2cb11b232e75c4b3695f2b28707dea05fbcf6cd4181e9e150210ce24ef1bdb168c381fde4e7895c79b0d81e8bfd43",
    "4d49500138be4341913cee1d92a79c3f089766bebaeeadf41286becfb6eacb192660c2007565bde464241f7a8248dca9",
    "c3b3ad66281360860bd8dfa8356d1cf2107789beb3b2e9ce0502aa8f0bc0351e166bf52aeb12ff82e3486911d34d7516",
    "4e7b3aff5f43671b9cf6e0374981ac83334266ce8c9341b7d0d854c0cb3a6c8847bc28294725ba37a66ad22b7ad61f1e",
    "0c5cbafa4437f107b6e7996242d2d8160a961288e1a5c06e13749e6772fc081ab1d139f7f9583745cf19df58bec3f756",
    "c06eba3007211b2445c28829c95e317fbc8ec51138bc46e9c6e6fa14bae8584aad4ebc46468f508b7829435ff124183b",
    "821dba9faff60ff4ea2c4e6d16e3926492544a8b009b4fc3aba68ced9ac96f7806a5b79ab2856e6e1aec3ca9be838688",
    "0e0804e955f1be56e7e5363bb3a1f25df7debb8561fe033c167462333c034c28da6d0c7479aac56c3ce4e1ad51f0c802",
    "98f8f35a1626a49feed82b291d382fe30c4fb99abb3257783ec6d97b6e77a6a9cb658b5cd45230c72bd1408b60c03eb7",
    "b9068d78a33754f4f430c87dc8a71302b96d8c32ebd4e7bebe8b9d2d7979fb06e72253088b75cf7711ef8da4e083c858",
    "8d6b786f5a6317a6fa5cf7a05dda0033f28ebfb0f5b9c310a0eac28008b9767aa3d9d2b079d34217021a718d9ac6336a",
    "2711fd60438050e3069908a83d7fedc4826d2bef4eeb8476488dcf2536c9d56628e74e41c2610aca3d49a9cfbae3b9df",
    "b65f8de692aeaf643ac7d5e69ea80509f22b017da4173f70dd1e16c315e0d7f950b1b8872b9f4fd5625aba826a017962",
    "2ec01b9c15488aa9d716e74040055a2c93d29a22e32dbf9a058745b93453dc1ed699296e496cff6f1c9f4986dfe2ed07",
    "b87242d119de7eae053e561a15ad6f8c66626c1c7154c24cea082b2a93eb293917dcb0f058d4f2ae9ea294fb52cf564c",
    "9883fe662ec40581763953c301d6692ed3a0c108a1e7160ee4f2dfa6693ed285749046984c2b0edd4f7576565d393378",
    "a132234f3d321c5dc3f5e1944b269301c79f022f3c997e7e5e4f95043ffafbbd76f7ad0e296693f43d1fce6fc61e45be",
    "d3b5ab34f72bf9b71b0434c04e72b5675592a33db5229301cfd2a87f60aeb7671814386b30bcc33d38a0c07dfd1606f2",
    "c363519b589dd3905479f8e61cb8d64797fd61a9ea7759f42d57539d569a58cfe84e63ad462e1b786580f87ef3817914",
    "91da55f440a230f3d1988f35b6e318d23ffa50bc3d40f021c3c0bdae4958c24c518f36b284b1d3700fedce83878ddada",
    "f2a279c794e01be890716f4b954b8aa3e216300dbbddfffca7ebdabd356480957789f8b7e6c1121b0e241600052ce8b5",
    "11a9cfb0e5952f11ece7990a9386d1742a42931c76e38111b12def3a37ddddfcde9adeb10a0cc32cbe19702984a00940",
    "bb243a0fb4d137cfb44e79f0049eedfd0b15a15d480d31688bbbde5a669ded42c7ece8313f8f95e772df191b7580330d",
    "940742515c7dcdfaabbe6d63aa402164b301d40a02e7d1ca53571dae7a3182a212a8ddecfdaa335d176f43e871fb46d4",
    "38129022ce949ad4b84769ad965bd86282f3d05566fb976715b80b4e1d5b47a04cfde06fc28ec4b857e8726e647a78fc",
    "99865d44608bd5936c200e0339dc5ff65d0b00a3ae63aff27e8bd63270108c0cbbd350492998df04980cf42a9b6df491",
    "9e7edd530691854858cb7e073b74ef2e522fffb1d24708cc1c7e27cda4eb215b3cf1d2e219b47a38424f761835856039",
    "9d17dee727eb35e6c9aff67b36baf5b809c467cdc18910b1e11dbf7b06cd1af87170c6082d5e3354d4de495a64c6d006",
    "bcc0c62c3dd00db3708f8f3477d51b42264f620f24b8d2bf15c1b79e46a52564f8d7e54e3e3781607895cda5859c15a5",
    "e6459788c37bc75fdb07ba0c0676a3ab7f229b1e31842e7b24259fd7f8bef472835ffcb86df4c1f296f5b195fd0af0fc",
    "b0fe134ce2506d3d4f9b12eaf215f225a223736f9fb4c42825d0497934c713f8c4618187ea7a6e987cd16efc1436876c",
    "f1544107bedeee1456e9af27a04aa4413cf7c89992ecbae6dd67016d151682eba842eedffdba60b4f1907b7520e3030f",
    "24d8c29ee139673befa63fb871873054b6f2cf3b9f326442cb15a4ccb01a4504f1e47d8d844a1be5bae7dfdc42cbda70",
    "cd7dae0a57e85b7ad53f5af620cf4d8ccea4d42879d130a43486ebfb33d3cddc77853b5337effcb5c5068778e580b3e6",
    "4e68b8f4c5c8b37e0d809ea2398feb7c132a4f9443b7950e2fee7d1c223613bddd06caa237df932bc4248289acf3ebc3",
    "5715f6b7ef3478ddf267616fc148cbe49052815e5e410fabb48a24652eda7fa4e87b40e4e98ea0845889e9e1efd390fc",
    "dd07d35bdb48569438d7e5b257720101730edebc5b64311394917e4f503c2fba646f12827523d24ae0779695f9c17a8f",
    "7a5b2121d187b89629263a4dba510cdf81f47c9fad1163edea7b59651a00726e1140309200da6d774a0cdd61ad1f4603",
    "605bdfb09eedc36422ebe6a8cee7d28aa0e736a05564a6b910853209c7eb8f372de705ca8951570fdf09822bbd691a6c",
    "aa12e4f287451c0fe0f6a27a3ada48194cf1764f0d771c2b67cdb156350d83845938fa0f42399ef336997b070e84093d",
    "4aa93e618360d87b1fa98b0c1149382ce97625a50614d1b70e25244b0c768347589e8d820d2059d1a466bb1ef8da0a82",
    "04f19130ba6e4ec0992651641ee7230d50b2ad80eaee68018db2a283ea8bf59e",
].join("")

const S_BOXES = (() => {
    const boxes = new Uint32Array(8 * S_BOX_SIZE)
    for (let index = 0; index < boxes.length; index++) {
        boxes[index] = Number.parseInt(S_BOX_HEX.slice(index * 8, index * 8 + 8), 16)
    }
    return boxes
})()

function add32(left: number, right: number): number {
    return (left + right) >>> 0
}

function subtract32(left: number, right: number): number {
    return (left - right) >>> 0
}

function rotateLeft(value: number, bits: number): number {
    return ((value << bits) | (value >>> ((32 - bits) & 31))) >>> 0
}

function s(box: number, index: number): number {
    return S_BOXES[(box - 1) * S_BOX_SIZE + index]
}

function xor(...values: number[]): number {
    let result = 0
    for (const value of values) result = (result ^ value) >>> 0
    return result
}

function writeWord(bytes: Buffer, offset: number, value: number): void {
    bytes.writeUInt32BE(value >>> 0, offset)
}

function zFromX(x: Buffer, z: Buffer): void {
    writeWord(
        z,
        0,
        xor(x.readUInt32BE(0), s(5, x[13]), s(6, x[15]), s(7, x[12]), s(8, x[14]), s(7, x[8])),
    )
    writeWord(
        z,
        4,
        xor(x.readUInt32BE(8), s(5, z[0]), s(6, z[2]), s(7, z[1]), s(8, z[3]), s(8, x[10])),
    )
    writeWord(
        z,
        8,
        xor(x.readUInt32BE(12), s(5, z[7]), s(6, z[6]), s(7, z[5]), s(8, z[4]), s(5, x[9])),
    )
    writeWord(
        z,
        12,
        xor(x.readUInt32BE(4), s(5, z[10]), s(6, z[9]), s(7, z[11]), s(8, z[8]), s(6, x[11])),
    )
}

function xFromZ(x: Buffer, z: Buffer): void {
    writeWord(
        x,
        0,
        xor(z.readUInt32BE(8), s(5, z[5]), s(6, z[7]), s(7, z[4]), s(8, z[6]), s(7, z[0])),
    )
    writeWord(
        x,
        4,
        xor(z.readUInt32BE(0), s(5, x[0]), s(6, x[2]), s(7, x[1]), s(8, x[3]), s(8, z[2])),
    )
    writeWord(
        x,
        8,
        xor(z.readUInt32BE(4), s(5, x[7]), s(6, x[6]), s(7, x[5]), s(8, x[4]), s(5, z[1])),
    )
    writeWord(
        x,
        12,
        xor(z.readUInt32BE(12), s(5, x[10]), s(6, x[9]), s(7, x[11]), s(8, x[8]), s(6, z[3])),
    )
}

function writeZKeysA(keys: Uint32Array, offset: number, z: Buffer): void {
    keys[offset] = xor(s(5, z[8]), s(6, z[9]), s(7, z[7]), s(8, z[6]), s(5, z[2]))
    keys[offset + 1] = xor(s(5, z[10]), s(6, z[11]), s(7, z[5]), s(8, z[4]), s(6, z[6]))
    keys[offset + 2] = xor(s(5, z[12]), s(6, z[13]), s(7, z[3]), s(8, z[2]), s(7, z[9]))
    keys[offset + 3] = xor(s(5, z[14]), s(6, z[15]), s(7, z[1]), s(8, z[0]), s(8, z[12]))
}

function writeXKeysB(keys: Uint32Array, offset: number, x: Buffer): void {
    keys[offset] = xor(s(5, x[3]), s(6, x[2]), s(7, x[12]), s(8, x[13]), s(5, x[8]))
    keys[offset + 1] = xor(s(5, x[1]), s(6, x[0]), s(7, x[14]), s(8, x[15]), s(6, x[13]))
    keys[offset + 2] = xor(s(5, x[7]), s(6, x[6]), s(7, x[8]), s(8, x[9]), s(7, x[3]))
    keys[offset + 3] = xor(s(5, x[5]), s(6, x[4]), s(7, x[10]), s(8, x[11]), s(8, x[7]))
}

function writeZKeysC(keys: Uint32Array, offset: number, z: Buffer): void {
    keys[offset] = xor(s(5, z[3]), s(6, z[2]), s(7, z[12]), s(8, z[13]), s(5, z[9]))
    keys[offset + 1] = xor(s(5, z[1]), s(6, z[0]), s(7, z[14]), s(8, z[15]), s(6, z[12]))
    keys[offset + 2] = xor(s(5, z[7]), s(6, z[6]), s(7, z[8]), s(8, z[9]), s(7, z[2]))
    keys[offset + 3] = xor(s(5, z[5]), s(6, z[4]), s(7, z[10]), s(8, z[11]), s(8, z[6]))
}

function writeXKeysD(keys: Uint32Array, offset: number, x: Buffer): void {
    keys[offset] = xor(s(5, x[8]), s(6, x[9]), s(7, x[7]), s(8, x[6]), s(5, x[3]))
    keys[offset + 1] = xor(s(5, x[10]), s(6, x[11]), s(7, x[5]), s(8, x[4]), s(6, x[7]))
    keys[offset + 2] = xor(s(5, x[12]), s(6, x[13]), s(7, x[3]), s(8, x[2]), s(7, x[8]))
    keys[offset + 3] = xor(s(5, x[14]), s(6, x[15]), s(7, x[1]), s(8, x[0]), s(8, x[13]))
}

function deriveSubkeys(key: Buffer): Uint32Array {
    const x = Buffer.from(key)
    const z = Buffer.alloc(16)
    const keys = new Uint32Array(32)

    for (let half = 0; half < 2; half++) {
        const offset = half * 16
        zFromX(x, z)
        writeZKeysA(keys, offset, z)
        xFromZ(x, z)
        writeXKeysB(keys, offset + 4, x)
        zFromX(x, z)
        writeZKeysC(keys, offset + 8, z)
        xFromZ(x, z)
        writeXKeysD(keys, offset + 12, x)
    }

    for (let index = 16; index < 32; index++) keys[index] &= 0x1f
    return keys
}

export default class Cast128CBC implements EncryptionAlgorithm {
    static alg_name = "cast128-cbc"
    static key_length = 16
    static iv_length = BLOCK_SIZE
    static block_size = BLOCK_SIZE

    static instantiate(key: Buffer, iv: Buffer): EncryptionAlgorithm {
        return new Cast128CBC(key, iv)
    }

    readonly #subkeys: Uint32Array
    #encryptIV: Buffer
    #decryptIV: Buffer

    constructor(key: Buffer, iv: Buffer) {
        if (key.length !== Cast128CBC.key_length) {
            throw new Error(`SSH CAST-128 key must be ${Cast128CBC.key_length} bytes`)
        }
        if (iv.length !== Cast128CBC.iv_length) {
            throw new Error(`SSH CAST-128 IV must be ${Cast128CBC.iv_length} bytes`)
        }
        this.#subkeys = deriveSubkeys(key)
        this.#encryptIV = Buffer.from(iv)
        this.#decryptIV = Buffer.from(iv)
    }

    encrypt(plaintext: Buffer): Buffer {
        this.validateBlockLength(plaintext)
        const ciphertext = Buffer.allocUnsafe(plaintext.length)

        for (let offset = 0; offset < plaintext.length; offset += BLOCK_SIZE) {
            const left = (plaintext.readUInt32BE(offset) ^ this.#encryptIV.readUInt32BE(0)) >>> 0
            const right =
                (plaintext.readUInt32BE(offset + 4) ^ this.#encryptIV.readUInt32BE(4)) >>> 0
            const [encryptedLeft, encryptedRight] = this.cryptWords(left, right, false)
            ciphertext.writeUInt32BE(encryptedLeft, offset)
            ciphertext.writeUInt32BE(encryptedRight, offset + 4)
            this.#encryptIV = Buffer.from(ciphertext.subarray(offset, offset + BLOCK_SIZE))
        }

        return ciphertext
    }

    decrypt(ciphertext: Buffer): Buffer {
        this.validateBlockLength(ciphertext)
        const plaintext = Buffer.allocUnsafe(ciphertext.length)

        for (let offset = 0; offset < ciphertext.length; offset += BLOCK_SIZE) {
            const encryptedLeft = ciphertext.readUInt32BE(offset)
            const encryptedRight = ciphertext.readUInt32BE(offset + 4)
            const [left, right] = this.cryptWords(encryptedLeft, encryptedRight, true)
            plaintext.writeUInt32BE((left ^ this.#decryptIV.readUInt32BE(0)) >>> 0, offset)
            plaintext.writeUInt32BE((right ^ this.#decryptIV.readUInt32BE(4)) >>> 0, offset + 4)
            this.#decryptIV = Buffer.from(ciphertext.subarray(offset, offset + BLOCK_SIZE))
        }

        return plaintext
    }

    private cryptWords(
        initialLeft: number,
        initialRight: number,
        decrypt: boolean,
    ): readonly [number, number] {
        let left = initialLeft
        let right = initialRight

        for (let round = 0; round < 16; round++) {
            const keyIndex = decrypt ? 15 - round : round
            const nextLeft = right
            const nextRight =
                (left ^
                    this.roundFunction(
                        right,
                        this.#subkeys[keyIndex],
                        this.#subkeys[16 + keyIndex],
                        keyIndex % 3,
                    )) >>>
                0
            left = nextLeft
            right = nextRight
        }

        return [right, left]
    }

    private roundFunction(
        data: number,
        maskingKey: number,
        rotationKey: number,
        type: number,
    ): number {
        let intermediate: number
        if (type === 0) intermediate = add32(maskingKey, data)
        else if (type === 1) intermediate = (maskingKey ^ data) >>> 0
        else intermediate = subtract32(maskingKey, data)
        intermediate = rotateLeft(intermediate, rotationKey)

        const a = intermediate >>> 24
        const b = (intermediate >>> 16) & 0xff
        const c = (intermediate >>> 8) & 0xff
        const d = intermediate & 0xff
        if (type === 0) {
            return add32(subtract32((s(1, a) ^ s(2, b)) >>> 0, s(3, c)), s(4, d))
        }
        if (type === 1) {
            return (add32(subtract32(s(1, a), s(2, b)), s(3, c)) ^ s(4, d)) >>> 0
        }
        return subtract32((add32(s(1, a), s(2, b)) ^ s(3, c)) >>> 0, s(4, d))
    }

    private validateBlockLength(input: Buffer): void {
        if (input.length % BLOCK_SIZE !== 0) {
            throw new Error(`SSH CAST-128-CBC input must be a multiple of ${BLOCK_SIZE} bytes`)
        }
    }
}
