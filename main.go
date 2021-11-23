// main.go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/sbinet/go-python"
)

func main() {
	python.Initialize()
	defer python.Finalize()

	wallyModule := python.PyImport_ImportModule("wallycore")
	if wallyModule == nil {
		panic("Error importing module")
	}
	// mnemonic := "supreme layer police brand month october rather rack proud strike receive joy limit random hill inside brand depend giant success quarter brain butter mechanic"
	// _ = mnemonic
	// helloFunc := wallyModule.GetAttrString("bip39_mnemonic_to_seed512")
	// if helloFunc == nil {
	// 	panic("Error importing function")
	// }
	// a := python.PyString_FromString(mnemonic)
	// b := python.PyString_FromString("")
	// c := helloFunc.CallFunction(a, b)
	// d := python.PyTuple_GET_ITEM(c, 1)
	// e := python.PyByteArray_AsBytes(d)
	// fmt.Println(hex.EncodeToString(e))

	txHex := "020000000101167b010b00b5fe90039e6e3bb9b4e038739901e0f3a33df8359e5e1fd7c8d9c00100000023220020bb14559fe38729067fc10b6193e04afc6a2e784d22c19bc270da5d349361baf0feffffff030b03a50791a956de471125d23b5d2b656b24d2eac0393d633f60a32164825d4a3e09ff34ba660c2783c667e575d54fbf45caf3f1ba2511789e79fc24993d1482c88a0259f9ae296d0d82e1573aa918882244844ea9ee96e909360c2a0d1f8ce588bf161600147d7da3c0507ce40839916292c8eca1adad1e32620a7c5f326dfe81bdcaa1030634ef67d0f66c4132e7ad9b0e319cd3c11627f7ba7f094cc8c288c47a4285a6e2796690745086f1d23297f19dcccca4731031d8e6f83d0378c2414bf7e415472dc746d9e9987ee52848065138fe29066d1515868a186ede17a9145937660abc902741d1b0acfa364bc2d3a02f384c8701499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71aa4443654c1401000000000000010200005e7701000000034730440220397b6b63c94adb098b6879c73de356f075afeb4f8825538436391defe1e400cc02206905da5d6e22f6ea4a816af377681c8293c6444b4fa0ec042309a90c86c37c2b01473044022068abf0c296f44054433460159036271a5dade9430720c4babce655aaa2164961022071f531ed3c63f546b9855882e0dac81047d8f306a002822b287dc69b3ad91fd00151748c632103102156e0a1b35f9db80824daf843d8fb9e84f903eb3498bcc09d53149f200407ad6703ffff00b27568210297987598965b6a98746f81f1e55145c646fb4b5d248b0d4adfb47dee8be1f55fac0043010001a18c248ae94d631884a59cd178380f1caaac610fdc9ab2d5b7f8505e506553ecbdc08e64d30a3407e49365996f5f167abd27f269154eb979759e297f273a577bfd4e106033000000000000000138c90a00c7568c81ce8b767b5ec1b7ecdfff5bee4626c73be8fcd751fff863aa2230639e84caaf814a488251359e95b42df4569dd5b323614fb08703a64941273a29d6f804fe35a56ad9464df4b7f8cfd3a415748d88b91d0f17ea64098b8d1d33814eddfb5de0de01b0900ec7a884552896abd39475e9595ce5d9b5300f4e94a8075853592ec65ec81f84dc8d68dee8a37b92076d56355693f22d25c4ef6b9a113751412dcc4c0753d77fd35bcc910b64bb506fa428ae695942d1ece81e47598416ebb711649edce195e5f5c74adeefa38ebd97a112b3c9a3951b18f716a3e8543fc275669b265277c91787e0664d2f9014045c947a3d55c98948725bc4ae7d8230edf4f03595e8508b40adb7c1978c2aec8bf77535753c967156383f5ba0170d774dfc7606dd6b8b3c899ef0282b53020540b3f1b0cc47e07a890f6c9f44f1c89180c3b41479b9cc30505635eb25a0925d4e9b97320dafbd6649ae049e7b2e8a53b5e64b86bb8ef5b83c6902acb8dd3c9a1e53272d9bd4c25fd5f5b61846bba15d8fc363882d2409a22d00163be1182c34d2178e6f29d52efab2d18987ca8a9c1a950bb966efe8a3eb29d8024b4f0c2b6ce828baef53e9bf09dec11c0f66ea0fb0621438baf768c1214beb7cf57254e9660cbc6836a45d3f5d216c55bd9285e2b69ba08930864ab115120fa2079d262996bf6ed998e6197bdb372c64557d5a10df89f9b8dcf3a94c43362e349c424362123268952f794054c7965cfbf0c0c62487db5780f48cad2c0b9da972b43abccecc2b10ad5a3509e28564b6c6ada7acbcba8ba418a825a3f3ac7d536e68ee20134a75f4de9607018967227e72668a4eed2d2e2533e8a9228d7c2f55834a74a7fc135c9976ca192e1470d54a8d06e943ee751393f5771a13dbbe0386bd3a4051b0ba4c2c3c67bb6710e782671fc7081098194b40b6f6ffb69922d18f343db79a1b5275fc809b6b396daef818cc51aaafb3b49e536c5477e0fa783e47af0a19585cc2da6ec2fc0f222b9f4fbc74efb8723f739c7f233e4641495a547aa102a50c85cd69e7ae3d5f247c0c10fab122aa48ac2782a73f775d63f85c8e51a0feaa0edd94b9ae5fffe122ac6d7c42a93b202f68061ab38541044cae0fcd28a4c07f62789848f1ca7e332b6cd800d80655ab25143c300eafe94a1a3a972ca755c911ae62a11c478ca8b5816c2955eec3c383d8e126419d5e320b276330e0220abe1f860377799bc9883eec8e0b09b267acf9a9648e135321df1c63d0f8f843d8dc8c4d2011e3319b06a77b01e2575d0a95b6e2d420d981eb2f45e77f2e96dc7e50139e4e33023dbc3f490d41221b017f26c7a32299566e41aa28a887745e919e1bba4e30c99f7cdc8e2c645c05c823881c19f26315adade03aa967998f61607cf0583cbed088440954bfd2aec675be3d77a9cd7cc76f6c6eab8569104058aedb32243ef07475a32eae4ff0bf7bbb819b48f37a1b0bdc8d47917761d27c1608c974c52b3d42aab8eaef13c6b6970644c7869b3c3e12b2e87c50d6813d08e0670bfeffa8b7c84531c1a0600217f087c57223511cc99ec01fd43440dfa1ca0414e51f8863f8ca07d95a11db89d4cf8e7af04604e2b8eb3da174e0c17c635a555f7ffd14cf3365d610fa35b0b9424bbca46e4d23815b1ed642f5cc71773a9f07e937d5a9f4f798ea744f3c317c77fbf82159514ceff783799ca21867b874f8984291d771a7f1700a44f73a19471b4ad2f3c374f0845e638a6329e201cb1c9d3d37feba09df702a79f67dd0bc7188b0f73fe20ac1814dd043ccccd0915ec4ef1728697374bdeedb1cc9e7bdb17b1756da36b6f0bd39fd5e821ee850c9553fd610bba7a4389abaa7186e76859b123f56694c05b471194b45245d3e6bc5105618d49e8fa4d97f3d0f38387cd087e7e623a917a53ad7673400e0e372115cfdb68c71d697a8102a5c94ae4df0ff88c1666fdde9b3f66e26a3c9a550beed5d9a1c2c836d7ce50af546f74e7af6cdd8bad4092974cc99e24b21ce590d7d5f2238616490fe9480c33ea23f0666474c2a83ddde4303c8de08264bbdaa9e510548e744578334efed49aa91d3c11b2f54d9182797105925b5a71d93d14a1abc9ecf2b398cfe63519c6d3fa5de07fa2f9cab4d8d45ab5f718005b727e337b4a5c6b765fc56fb6a1828773bf433f8f54b10135f04f1c50624ee5099154a0c690987b73935bb4b34eba84cba894909060f1333463bf8d47a2ac3f36547eefdc80fcae2ae38e722bcfcb67de46dcca5bdb27de1a525d8c97d5f27eb8c195e4555a4369ecd94949af39234b59a8a7f871490657f0ce4ca505f50dab93a8c35604b9cec0bb9977e011bc35fdc36ec416d1691f83b8640d17e890dc537d3dca627d18b0baf9c60ef3974bb072683479f2c3d1fe91ec7e491664a4268a7d62dae72d68bb8af042acbc07f4c5bd1516d913cf29921ea9e700f031aeb81b6c21781cd9b3d96775352040fee481ff528bbd74a66145d7cc67fdb6ccee1f36683df6eef694135c10a0784425af7d6fe152d3a944e99586d41356bc061a60dd6429d9f172f40a7d04ff1cb2bdeabf42a76e15a86807f29c8823ebcf3049006bef649a85425755bb8ac28d0f6bf0f0aeb5f807405a5ada332f97bef9ba917db3798c02c57104837f5e8d318a02a3a86cd45777fe33a1c7ca0fd0e980385ee27beed7fe82d2a09d1adbf4b103b157eb4960bc03aa08a543e59f102c689015dbc08fac8dc42dbac3ccd8d4f7df393a80df2b73ecaa630ce99e8a1f8768784a49652ae85bee8d570b5ce9d82a538306ac40b057f166229c8c825109946c85bad299d7ff57dd55afe0ab297439566f37e7342b5d02a7ae7c79ac52b3bcf8455925e9797baeaff82a7faad01a9c9939c23896e2dbfee3e862e92a6525295082e1b96b2899640ac5144efe4bce95bf2d33d2f358ae6bc351a92a3fd7284a1cb1c56f316d5a59c2457b5dc09f55637d6d8aa57ecf54fb287cbd4aa6b5956f5db02d340ea8b7457f06172549e4f5c931c892fa7158a5e6f2cee5633d23a6f5631b34f4f95f7045589e94a819c1c2d4aab174ee210a91811f9dc9231532cb3d6edead046f0f323cb2d8c665843ac20ae4398c7ab72bc49db38cb8464288a6bb1fda3cece4b0863d472a6df79146a51892aff4f94f6b20101f24f3d32ccc128baab2ec5fef4eb69f76c37124d4ab6a9faf8c698d78e0bc019ad83a8cc95b275908473ec31c79f90d0a720ffc698e1c21e29a7e89c24f22a2f6a73338dd16632caffa1571688c69a8341275465bdf781ca33b11bd1bdaa4c89891251465e3dc4d541116b9b4be7d7e32a1c571f02c267785889f036f021e98de87e307511547d77326e2fb412acbb826ba553d8d51e97bb559b034c01cb4bc0e12de889cc4691aa883405503bcf7c6defa750eb86c522200756b878ad7fd27f881cdf408efa63d32743cb3968cd22f8cd8e8fcf8b9ad204f8327b13237a1989f69b123208067db6162547b145c75397dba25d9535e53ff8a35344cca58a404337f7070d353d61eec42c355a8116ab9630c48dde4b6af5b0ff7699b08e3779ce661d9dbbe32431e7c996c81c4cbc9ec19e914faa93bed734a763866e5f13675f6d32b95d27d58c6d4a9820c152432e43014ca4d4ac113c6b2da2815d41b3aea99ce949d2b13fac6682d5f429c5c013dbcd0522b1a1ed1fc76eec0c107c48192b1d126fc9b7d72da750b18fd72b440c3adaefc965408dd5f71c75bdfb6f370921cc5e6988bc7381ce6bcf182933c9e97f71f80941342f1c67841f1376d4bf055702264d26a5eef39be26009f55856f594c2d17dcd2c7218815396a3c01d6823791fb72899694c6d28f5773ad999eaa167ad4b17a99e71ae4786f0bfbd2f3df065b9101e54821dba908e438fbd936bd5536c789421c51e60a096c755eb2b1ed8313ff0ed0d6b75e6a1cf04e92f7a6b8422822f85254328fecd67a4692e3cccc417078da274fdde40cb40c9edee2cfebb84c74c2a2a881368d47ba2da0f926ed3b20d3331ed0e8c09c72ae462e9ed08b05dbb47ef7c0651cfe251e90499201b368c5e87e38adec57487d9b27089cd11a94655967a476445ab8e244333f6d817ed442fd82e70a52cd60c08dfde05c0ccf917a9f82bd1dcb15d4beef82ef6bee33c8a0f49859a968c12f50393d8538300c0b4eb1de82271e43a993e6d45ab68f0e450fc5b69d31b3a3b48bbcaea7722eff2cd91aa6902921271f9514f35a7eb8ee46812115f47e6105292a879a28c28700831282f4b05c1d9aa706ec43eea7b15ac7265762f6638e096c7ed472dca0ce48d8187370795c9f7b328b4e2a7b6a7e13533347f57c6ae40d06fca55ab9a7653eb24388d036411c335e3ab8edcbfc4935f002f55c8bef568075fd5b88679bca6c9130f4fad69d11487c4362f9419dec8d1b071b2dce2416921cd44b1dcfd684cf20ad56ac70ccf8bce48979772650daf330e92e5dafd5d2cd9e30418ad2a34c30ce6c7eaf58ea79484b0238c19768e0c892e49db4072796a6c534dd18a57ac89edd2f94e70aad3d4e62077bfdf108e37443cee8b0705830dab3d42acc96021aac1535be90257340c73194da98362f9ce4106edac44b8ad4776016240ff6f5878b1f19682b6af2cb3192f3776ad9cd5877d8e50393ed429488203ddb21b6bfd2e826666e4c707dd268b2a3514ebdddb575a4230ba22061d30482040b1d56a3dd9351a54f8004e73796a66b95625f415e558c228aabbfbda61a618ec7e01462f8546fbf329cbca3ba14eafaaac4dbfc50ae1bcb076c4d22612dda72dbd0a23fefc4aa291cf2be3db7d81d7acefcfe94b1b38eb1c169cd72c022b8ea1efdad4caf6a17fa3080a2d74ad82da342ae983f9876ac1fb4b5faa584329d8df9d16d6708fdc442681ce5b448e0ebfa3d8c341753a45f5823b6b1fd5ab72ec5909bd6f1dba4cda9c82ab9f666cf059e5145a6af2fdfbf0b55ef31fbae599c0cff2afa4dd9df2db7042c9e711e584a10df4fcbc48335c6f2ae90274acdd2792dd402cb32e742892f32b36308768186ec502b2ad7ca51d37c7bca4c4535c1ba5a4b2ba744105f7d8f60512cf2ebab6b9d869df8a7cef740fc7617a6c97c41275a1c4aaaf8003d57e8c5e6f523820f8cf3cf6a34867960041b35fd57e72a47eb311579f99df2fa38bebfcb5fb2010071cd7fbe7da17d52304e13034f4652b5b91c9220750f69fbb857619da088b5298f1ccc65942ccbef582d94e83dd9e47038fc1cddae00fbefb5a713434279e8636d9d03e0fccdc1daa27708c23750cff1d7c487a3bdf51b7430e8e106c55e5a601384422de8c913c3c0e1259a05529320dbda83e8d89fb274f22645fd6ef2d77bfe652ac3fe6bbe1ebf8810ea7a6461d9593bed741f0c8f7691f024e2242c3b08177e3b08fabbefc37275c8e00a970b1e2120b3750ecf450013b2005694c6a2bd4c071d921699a6b90b619bfc8c2e02c2f8644f2044c43e4790bdeaa1c27cf28cfde7d00ec92598dee985b20ae203b789514252709715c18b23eed21a2a091bf8df42c47d0be9849df9621be3d54d3f1dad99a7751d8549166754a776a1299bc105159d1cba1949284727fdd7c4c64b8e1abf4cb998c84e62f0cac07e215fc464578ca5156c1032ccd567e7d065e309802d26f976331dc38175475905f8dc2ae33190432c655edbc9745de27289df50740c450c1d4202f03e1cc9ae61dfb7b23a206c0e50d323ac929b52e98eaa837328a0fd601f59e3783acb8ee470de58e3d30b49cd044f93aa808489515c9c61591215b109265235f5b3b98b220e03d0715feccce3ff986f4838546589e6638987a820f87d736c5e9282741f03b4301000130adc3f39f2594eb3267ebb52aa0759303ee05446f0d694f13c88f07c798dfbeab850eb7ecfdedb054766b510d7441ed5cd44c2d55fce3d1cb29366002d15773fd4e10603300000000000000019286d6006ef9c39753ce5439664edfc7801ca121d24f0b96e032cf9ff45d986885d8b0b2514b4803277e2e5d1302baab714e352bd9bb45d21abae2976d69bb5bfe0bed10519e96b6a3865949492c58955c3a19c6ab0809de409f68b474efaf15a872de64eb7edd20d67f6b15951ca308acb7ab8f1cad5d977e45d2030bae86e15825300f1b9ed3e1daa5e1a56685d66c440b422b71dcd1c40e3c607533bd03499f9fe3e327adeeaebbc6697c3800df53c503df512ee095c3f52590baf0ab18327b2430f38eb3e59a96435ad9fcf8da9497a3d570330fe2344be5786f5d9e75310b3aa7e31508eb80df66e7a50cbcd76739e723ea7c6e0557c3693b77e50b1fd3b9b9fcd21129cb0fa9928e6300cb927548b1dc48f89f1eebf607c20a0d7289690391aed6ccb02a69e99965c38bee463dc8807c64ff29da4878bd2a05460f346b0c7295f6f0e42b95cc0c81c16bc40b43fff3cb0cdb58ffae8322a55c7a5d8cb734d60287f45255cb2101389b2bd556ead6e6fab3f934e58f21e23fa8245d64b47913257abe3985c75d65bbf9be06b87629e47b4d10c0e67fe83b974f11179ca35438e2ac8a0fd1b22c4f7791b35378c57299f0983a30c9c7372c43bba49562b1f8b7a01698b2baa61b3a21b56653b2aed2c3c4f190bfc283575bafd7e86e0c69f1ba2c01027adea55ce88186f4c3f94bb2efc8f29a3cc6a3647e58cd5a751730088f146e650456cf69fce22daad6674b17d31dd7fd8aff2abf221b78ab5aeaa689a91605c7d3814755d736211344e971fbb2cce9022ac8d7375fd4a07366b0b914e4728610da1b3487fb73119d198bc034d7daaab2f231aa8dbbfc81916bdaa73bb6b0746b32a30e850b615e4fb8b218977af0207714de3a1acb0d08b474ae51e8c5c492839855df837364cea75899503acf51d4e1d8bbabb99fabac73610f5cb6b01ecb66bfedf8786de9fce9fe3fcbc7844f174feac3dba86e71606424801113e97cc3c973b62248ef806fbe8ef604ddf911652c8460770a020431fa0799a02b23d3d56f86675e3b80521c3b9a18a31d452af51c39073d47e02883e54e516f08c1648ec5b08b7c0ab6f79151a9f4974fa0e0e61aab7d125966e127fa931e7c40aeb5002aee794cda77453952787e8938a42a9fcb09a8b7730154d689634a8a7f32c97e579be0428232e1298f9e646de591924c9609f04c1b309ceb45ebcccb09e0726072cb83c6cf4ec38d68baa4128fe92a41be2617d44d41279c75ceb342e630ed7ab540775b8e9eb9df8c8491f93f2d62b77d17f4a344ace3d0a92c5fddba9a37a3c7651536addd6accb5473a8e120662161810ebbe4c1ad0ff3d080343c1699a1aef521988161253fb1a9b183587f3a32ccdfdf8cb8f5c306e0bf067553af7f342aa144563b2f395efc923f7039d66f07ebc59641ed0eec48126827c7173297038aa146b945262b60a78a30f291ca3ec17ff4a234560a96a5585c0d4dd503e2d19d6114f1e8b4c2e26644db750228417a2359ffaf0d4c43c030c463e3b0f9d7b7e7cf4cd50cb0f1e21ea844103e8467b12dc5a050dfc13e23fa20230050bc44c39418a5d1f29b7e02495bae0a5c0ae0aa92fa21a424432d96fed69e3cada03dc7a1baa21babc01825a079fc847c3afde027ca256614ec906f68c7c8dcab5ec5ea8e16963720ca97dbd13574771702241d5c7a46c390bb1b929195fd04fe3637d342b597508d7dfb1a2bf2d99e990074b88420e4a2660ae5dc34f52be03179f5213fcb94d13b2657891f7d648f006fcd46c751b5f82ab8544867b0e6a1e97dad0c8b391460efd2d373e7cfc99097ccee640eaaa779ac738efeca7a5a047b7733a92b069984fa3ef6bc13eee16559d112adb8c03c5a63559cb53d872c0e0bf8b4d6bb8492d10daff2eb861c57afa26cc6bd07e12e8901e68ea12a9733e76474205036590fc8a7b79bcb1a416ebb0d124d166ea04a7dbcae04cd5e1e197c0622a759263f5dc830564a2c5dd38ee9197e0b0f6ed7ae402a80ca80b97f04770357adfb5de858436431d87cf6c01e8c9b5e42281006a448b4f0f62663f27e699d69635d9a27c3ff1963f8537b39863f7a2d6d832d2ca19eeaed7bbda1a0cb44de322115095f9fb08c4d36b673b8e7ebfb989341bee2c41d1090ae5677a34d1664fc6995afbae5fe992e8f78a87645710eb5c2458f22a506fb9ed238acbdb06b8779a99c4d34813502186c4c6eca9fc2d559ca94b81f0eb51698028c9d0dbe4dfb3e36f702244dc65c0e96047c712a588f2284d2aa1b5fa1d12135961f31d546db687bb91c6d83dfaf055edb6cfcb82f5c7689dd7cca6f401cf4dbaa7497664b6ff7f8941977cfcb5d95c6c7214eb9d086c5b7b9db22ab48c80d353c0e5c46f5666cf024704ffa86ffaa4ecc0eac06dd750e8b802014b5a309e76a0619949f486921bcd8c36d7b2dc1e595c152275d459783921f6135d231e4dd691d897f266a39119d40727b54d26fd0b2fb650f3021c7d3e8da8adade0f5513f85f3ce9b6b5335e69d5c1a04a28eb32443388279de0767e835a71970be647491c669d12f51f63c2857ce1f0f0e62c0c9bdbfc5d3a1e516da05644c047528f174347d8a7992866243952f9a67e8c4d9c1dcf35e971106514d93e869906ab8aadfccf06dec985345ea8637dc1341312c64099de2b713acdc77f4615e54edadb1be014eacce24ac086cb386436df54937dcbaa95422a01c0ac057f0c2a44b82bab7293a6380c5bd712e52fb9d0e37d84b54d67240e26bd326f12f4b1e785167af68670d322c4fa85c68e14250d7595a738700a81006fdf8486987e7b26e12e6ad41a519cd4ce5d56541712fd71eb5d5979fc5327eef0811aac9aa470a84f677d90e44d2b233efa829c66a314b2a6f05236168723e93a31fdebe9c747ba147894751d398e0394ac608d29eed136e13a54bed1e01f28a9380db263c66255db07b6dfb14b73c784c73028464516636c647b22447b75aac1090f9e636ce6610383cafb4305fa176e93519900bfd92c6bb5bb0e32615eb777419f72df449dbb664e8949c214a7acbca6daf390cb282a9aaa7ef6d4f75ec032588f35d8fbc5a3fcfa9dfa8b11baeb9640f97730e40e9abf76aaec42c3b0593ae423c8e4e6919634059d2d22ac8636d12864ca7c06795f5d428dd643edfee6b42a75e8da38335e60d9ef99c0795d0fbfbe59682067da56d77c30785d60dc0f388064967f97b4999a3466fe3587e45bd8a3fc0a61eee170b23f8e6a4c746328455d37f54711df40ab9018658ba747edd0a83419990f9dcd39f18f72ada16eebfa5b11eafb70c5545d9475aa12fb845ba37bf8cbd9243fc849ffa5e8dfb0ba1ebdb2d31b2166b75e7f1facd78b08f515e6db0d88c6f339d3c4c8e139a7a6306e07ad482a601d8252144e09679e71d99af6a99b08f63925155b2d3619c7259d844eef35fbf3d8e768eff64163a414bacd7500a72491ce700cd795e634c45813c0f117502313f50c71633015c8472e2d0c8f5c61e1182d8c094bd2e0f76e61e9c35f45b984707eb6f1611f0c18a423632f1e00ac428e111cc6edc9ae9e2db2a175805f567af5472a0aa4e22d9c1ffb5c93c9f33264993d8d0b9f648c91afbe838ae8c78b7c67f97ee13b03ad5776f21dd965af5ae8910bd681ec5732209f537fb77698d6497201d45ce3814b78cefa21facbb5800be008922c98090d47c019e98f62e16d6e2b8e7fef59e14515c50e687e5f43f9a5f4e5d8b907d76184e2c335114cfaf3086defc6ff5b7a0af753087bd97d07f4724e863fe07ab8ea70dad2de3aedcf60060e76132e883a661368f9c6e2960d28154fa2962a49cf0d9a684674a5e098e7bea4e90bb355a62b1687bd50a7aff74efa858cefabc708958575cf7b93f14efae3fcf627e7d00edfc49207bc4530414ed9be301d665802f83f6001487264263b89b3b8204d865251742c4278acdea57d5e3e6aed0c6d632c2f3caded2e2688e45300e78074314b22f32009207b61b9f4d78704449eb3490f30b36a9f1b98d5a1d8377dd6f9d590c8832db1f8ee656ca0ee1ab2df22de409ed76c8f8831a9508f6a602e1e908139495b3d409887abe49fb0be03dd723bfcde997b2ab4ddb697566c1ca8642d2c503e698a3618c9b536aca238280299d1b4ee810973a34a84f38018c71e4f71d29bdd9550fcab33e955d7a140b2a4d54e1c76fb52fc671a1bd8635cb5995a788662e8815d0a70620d7c9883dc61cc98c823ad3dd31a7e13f03efbc5e42d8c0762a394b0f84cee0d84b31a8a94f27ef578eef3a08b93b35e36838826c2dff6c3b6a32cac1f29b5315b2cd9ad8a662edcd1513928d25c9bd466e8d6d8a00f67bfd1656cd2006ea5ff2b367d77dd6514cdc556fea906ebc3b816d58593e9c30672c8bbc9771fb9e332de4d23c23474ec82844a420afee3928e46272eb893a0f955031cb3c9526fcb335df477ebf22e86812439764898173383e1e891dcf1c64f9e7366d17e9ba8be79385161cb7681606c556f211d18ed77ae15708bc893e2b80960e2834797db9da86b3c119f09d0c8dddec180e071050ce54fc1af81de507524442c6ef701f1e58b1849320426b902a863c0bf904a385a036cd9a986aaef200a1b6dbbeca5a2bc96b8999d10f7a0a8b9c1de46558bdb7637c13b4014bdda80567deb3c6aef66869fdfad2c21108d1a74aefd7bdbeb37465ac1685b36a7cdcd85c5c48e945bbe90c4663d8a974817c028e70beabd6ee52cba43ec2fc84da0aad29f8abfaf7f0579a715251819e65c8e95d061568e8b117e63a2aabb09b034a28feaf185d1fbb81a8185a08812cf97dd9685543595f27fadee665f7b009ffea220c59cee92733d1a1a86e56cbcad885522b8b9ca0ad44043d6cedf2756aed45dc55323af1decfa417eddc6d6b3ffc80bf94eeecfcefe038d52c71f3b47f105f67e10e03ecc4d76398cbafe215d9cf5cc3572c7b23d201702689e7b7ee1bd03fbe5d2d42da3b956f7071d8cd91066cd75d5793cf84aed08f62182958544ed02784a363a59c2ca0fdb8ab04cb705573c02fd204bbf00baf17ab9beaa4bf76948c3675683337f85cb7f2353fa7ebbf19bb2ddf9124f4de2962fd4e6d024507a24181d76c8b40dc96df5fd99d9dbfaf4ee307bc3855b28ed349165540bcf8df0f67f0364453456a8d5a0262aff75e4556445f836f4f4d14dad2c6286d8b5f7b9be916148c290d2c087effc9a20a45032c3da9bd8e0fc20591968bb5d17ce903d7a5f2c0e2d4779432ca6c866d8f1c466ec7f014ef90af26652af0cc4db1870e085552bd66f7fa15c630b33610f8c69b22ecf32e2b69cc8bfe30d36be572532e3b995d48264fdf52675fbfec816d3c4533e251f02ef8647518cd28eb6c4887ca6e9d5f68e8229263dd6df1a8e126d0c1a5fa91b272b411d34f294d395d2636c90ed1c727759ef76899a9f36f828ee0c11dad36169f9e6b3073a1336da8fc797e09cc679378da8089ebbfde85d73d7480f592077b822a289e85ecbe67f324ff656c6e6a48ba91b328f33af8b2dff40590b0736906666d47fb100c7b06f9fd709534515a390d7abfc877d8f4848446d237e4dc77193317e0fee5627bc9246ee10d694f506198a9c3aba299f5c737e1540c8969a9abd7adb54f55f83e8bdc79c657afcf2d2e410b86450c2cb345f99db28099ac87dd4f2ad63870764ac052203053b1d99996a891da7c81a9d4a9b4a35399be2c89994e912fdedd6391288fa3a16d0228e852c9dd48f2a5dc284dccf4127ac59f9e3dc08109ebd2a83422220dfae4e428ecca8a8e8a2c023b885458034bd4b22101d57500ff02afea120b3b09795d516e6b3e40de8ac11c099ba8740964e45e080000"

	txFromHex := wallyModule.GetAttrString("tx_from_hex")
	if txFromHex == nil {
		panic("Error importing function")
	}
	txHexPy := python.PyString_FromString(txHex)
	tx := txFromHex.CallFunction(txHexPy, python.PyInt_FromLong(3)) // KEVIN HACK

	// Define Functions
	txGetOutputNonce := wallyModule.GetAttrString("tx_get_output_nonce")
	if txGetOutputNonce == nil {
		panic("Error importing function")
	}
	txGetOutputRangeproof := wallyModule.GetAttrString("tx_get_output_rangeproof")
	if txGetOutputRangeproof == nil {
		panic("Error importing function")
	}
	txGetOutputScript := wallyModule.GetAttrString("tx_get_output_script")
	if txGetOutputScript == nil {
		panic("Error importing function")
	}
	txGetOutputAsset := wallyModule.GetAttrString("tx_get_output_asset")
	if txGetOutputAsset == nil {
		panic("Error importing function")
	}
	txGetOutputValue := wallyModule.GetAttrString("tx_get_output_value")
	if txGetOutputValue == nil {
		panic("Error importing function")
	}
	assetUnblind := wallyModule.GetAttrString("asset_unblind")
	if assetUnblind == nil {
		panic("Error importing function")
	}

	privateBlindingKey, _ := hex.DecodeString("06fb6524493f1523fb1538fe1412efd22c68bdbe28db8d5dbe49ff5ac8d3d9be")
	blindingKey := python.PyByteArray_FromStringAndSize(string(privateBlindingKey))

	txGetNumOutputs := wallyModule.GetAttrString("tx_get_num_outputs")
	if txGetNumOutputs == nil {
		panic("Error importing function")
	}
	numOutputs := txGetNumOutputs.CallFunction(tx)

	for vout := 0; vout < int(python.PyLong_AsLong(numOutputs)); vout++ {
		senderEphemeralPubkey := txGetOutputNonce.CallFunction(tx, python.PyInt_FromLong(vout))
		rangeproof := txGetOutputRangeproof.CallFunction(tx, python.PyInt_FromLong(vout))
		scriptPubkey := txGetOutputScript.CallFunction(tx, python.PyInt_FromLong(vout))
		assetCommitment := txGetOutputAsset.CallFunction(tx, python.PyInt_FromLong(vout))
		valueCommitment := txGetOutputValue.CallFunction(tx, python.PyInt_FromLong(vout))
		result := assetUnblind.CallFunction(
			senderEphemeralPubkey,
			blindingKey,
			rangeproof,
			valueCommitment,
			scriptPubkey,
			assetCommitment,
		)
		if result == nil {
			continue
		}
		fmt.Printf("KEVIN senderEphemeralPubkey: %v\n", hex.EncodeToString(python.PyByteArray_AsBytes(senderEphemeralPubkey)))
		fmt.Printf("KEVIN blindingKey: %v\n", hex.EncodeToString(python.PyByteArray_AsBytes(blindingKey)))
		fmt.Printf("KEVIN valueCommitment: %v\n", hex.EncodeToString(python.PyByteArray_AsBytes(valueCommitment)))
		fmt.Printf("KEVIN scriptPubkey: %v\n", hex.EncodeToString(python.PyByteArray_AsBytes(scriptPubkey)))
		fmt.Printf("KEVIN assetCommitment: %v\n", hex.EncodeToString(python.PyByteArray_AsBytes(assetCommitment)))
		// fmt.Printf("KEVIN rangeproof: %v\n", hex.EncodeToString(python.PyByteArray_AsBytes(rangeproof)))

		value := python.PyTuple_GET_ITEM(result, 0)
		fmt.Printf("value: %v\n", python.PyLong_AsLong(value))
		assetID := python.PyTuple_GET_ITEM(result, 1)
		fmt.Printf("assetID: %v\n", hex.EncodeToString(python.PyByteArray_AsBytes(assetID)))
	}
}
