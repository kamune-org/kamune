package kamune

import (
	"bytes"
	"crypto/hpke"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExpandLabel_Encoding(t *testing.T) {
	a := require.New(t)
	info, err := labelInfo("key", nil, 32)
	a.NoError(err)
	a.Equal([]byte{0x00, 0x20}, info[:2])
	full := "kamune2 key"
	a.Equal(byte(len(full)), info[2])
	a.Equal([]byte(full), info[3:3+len(full)])
	a.Equal(byte(0), info[3+len(full)])
	a.Len(info, 3+len(full)+1)

	_, err = labelInfo(string(bytes.Repeat([]byte{'a'}, 248)), nil, 32)
	a.Error(err)
	_, err = labelInfo("key", bytes.Repeat([]byte{'b'}, 256), 32)
	a.Error(err)
}

// SPEC Appendix A
//
// Key schedule for a recorded X-Wing encapsulation. HPKE encapsulation
// is randomized, so the test decapsulates this enc and does not call
// NewSender. Inputs: seed 32 bytes of 0x01, info "kamune/2 kex", export
// context "kamune/2 kex secret" (64 bytes), TH_sh 64 bytes of 0x11,
// TH_final 64 bytes of 0x22, cold PSK 64 zero bytes, resumed PSK 64
// bytes of 0x02. Exporter label "kamune/relay-reconnect", empty context,
// length 32.
//
// enc:
// f458bf74a5acc535c19819ffc00c27daf369f8bc3ad338ff6bcd1d36135d8568
// b522a7d89526ecfbbf475a274d432dbe71c6eab9c1e56920c81ed07ce3be2d0a
// 8bfa99cbac95a2efb64d3d29b90d805b21d8ce2b6f51dbf6276fa9338701e427
// c53176f8db816b245091c63acb8bedaac267646baf04f4cf2f92a9d87e3baba4
// 9b174d116cb90f0f8fe12f59928ad78ac3d633638da850b452625c47ce730fe4
// 4555a7008ceba96eacbb9127c592cfe89f236ff66025f1ebbb12d96d026da71d
// e2c783ce8f6eab15c305f76eb174ad06bddd86c31496885b745b7223ae7b81cb
// 4439477e021043c8fd5c7fedc57305104b9ffaa817624caaf63883a39e4be2c4
// bcda04a45de7be091beea4405750c868726a9347d8a445a16891b0ba33213845
// de17b5f94513e0ae965826f44c5186dbc933b3e6f818640e063567433163246f
// 7a26ea2ab2c7789e06e7ad95521c856b71267997dc00b16f81b0b2f211cdd5ac
// ba827de54f1cc160d5e3f049e3085b9d60d1e9664b8c67b759afc08fa20aded6
// 473068b515e14d9bfd015f7884e2b01b5e5699dd5d6086419ae8a74bec14d50d
// e9e56dfb5513cf5bce743369c2df9c11ab473605893f2ee08aa84f8783b9ea71
// 63c6d47d480535c47f8c5b45db9f9b58e10686bc3b8cf8bdbcab0747fd2d439b
// a0d90ac204ac6198d4140f90c0f931ad07681c2b762ca4519fe9bd9b29e254ee
// 2a2f7688eb577b863f501519f35d4fbada04fb1c790199ab6ba025c63e01e00c
// da450b4cdef15fb685edac8abf455c2c63c6665d072215cf6d6330c5b5daa467
// 6fd1d2572c2c060c14c6c5b689b9abab06bcd2ff4a67640186f11d1f86e3ae29
// 64f5238e2aa87b44421d782f5a594a21eacf95c7bcc74f5b6ebfd50446d84de6
// 102c54273d3d02ec6eeafd069b709f40f56d80f372e1d081b642529fb88d417a
// 2c3ac12eb7b7e6e43ecdfad0eb12e59fc1314605cf649a7df69a2f8ed19169aa
// 5fb5cf3b0bc7b2d6c6e53b7b3f4da12a9e1b1e2c16fd9a1430b314ffab9613d6
// c5e4c42f09a4d0e4d2fcce06335e8ffd727491964c812ed543060bd5764b2e7f
// 39277a0d7c5f8367a9aac38ecc9791d95468c38f4b70fbea76ed657729b61d35
// 2d79c2a013dec37acb6dac31bb671f96f68bd7141400448d7c74592813419ed6
// b2fdff5aeb577b5980f1ba71e43e200037e722f0d760789c7b2e40524472a045
// d8723cfb43616f0940dea1bf5965e5dee6c2a60c423f061424161e9e397ad38d
// 7d9261c437a07d016091315b8f07fa27edaa656210edd052e45f5f9f3e4ee565
// 3229306ea09d0c337f05baea8d0d0476001d8b284695689f7abdbf21b1f52f79
// 2ff7db462507a05f1d220235fe22fa474bb69a7620a4f24ece5e16e0924be313
// 17b5cda316e87b42fd747651dffb094136fa2665289a8d4b4d038974c525199c
// b242d6bc385bdf1d8252266ed8dca73c118036b8e33a15172259d72a22e28504
// da90fe6672b5f69e751f12a970c6478bed9c3502c71f30690e7ef4c99a67adfd
// e9f18a822fa771a7b65e33e462ce0f27981e8de48e24e02a547321b554ef9372
//
// ss       35e13caf96f5ee212abd6af65d1c67f88193355a7b2499db5e1c510aead56a6085cf8df40dff2c8178603fcbd0e2f922786f3148600b12251c353d2731a03a58
// rKey     fa6cbf226490b3ecd973fc2e0294f28fb5cca534b807f4861c9938bf9086211d
// iKey     92f5c5413e5aacc4bf8e60cc208ef2b77c47a2de02e55cc63d3a59b64ee622d9
// rFin     283a067c1ea05c6a8ea972052df529efad6cfded310e385c3ffefcd6a8f26e03c61eebc4e83fd8508801e377c4061580aa4cbfca171c7a25baef0396be9af0d7
// iFin     7c2daec136e8259fee39813492e7e4353e6d7dee496e9e3f6ba55f03816d8aa3e29b9251856184a46da050e13e0084146b43817092439a6535611fd478853182
// cold     3483f9c1ae43bed63abf935c5126f5febf9f182de228e761a6917e6da9563d2a7702591050de9b4d59661cfbe92a4b5b3f992ada50ba07b6d710e017557ee04b
// resumed  bb09a3a9467c93dad7ce1fc9c4e0c53ab9ecfaa17791aadb467ade89e7dd9aa73adbc735595c6989e989b127c05de9de7e85cb52554271f04c38be23847a49a9
// iApp     10cf316c4a38f39776a13e8607569dd1f0a6349ab3a1c4b1f8333cca96be41d6
// rApp     46b3da3eac751d1cd3992aa2b3d253e9cb668190738d6c9b7307c1001593f0a0
// exporter 60e7adc095d67b8c0409ac94e2b659c8ca92e6e36b932026cfaea16ba06c8a82b8d00ab256c775039cce051f641443d7e254ca34186c37f13459c8e622d7d3c8
// resNext  64fc2d1c8403ff9166bc313764705c5786ed5fecc9319df16b15cf2bc163012f1faed9b96c0c61dbee8888c9d57436572dfa2f9605fc7989d20ef2e902419776
// sid      a56ec3c0c6dd3bf717b137a2063a38
// export   8a1f917d55d6fb3170370cdfedaff3e9073a6fb704fca0d9f607cba05b1ab414
// confirm  c3ce0328416a40489465c5d252869551687d6534a9bd08f4f9c2d1c90734f6841f17c9e0d236a4e893d871d0984a4014c125337deb59f401a406e93c0893cd8e
const vectorEncHex = "" +
	"f458bf74a5acc535c19819ffc00c27daf369f8bc3ad338ff6bcd1d36135d8568" +
	"b522a7d89526ecfbbf475a274d432dbe71c6eab9c1e56920c81ed07ce3be2d0a" +
	"8bfa99cbac95a2efb64d3d29b90d805b21d8ce2b6f51dbf6276fa9338701e427" +
	"c53176f8db816b245091c63acb8bedaac267646baf04f4cf2f92a9d87e3baba4" +
	"9b174d116cb90f0f8fe12f59928ad78ac3d633638da850b452625c47ce730fe4" +
	"4555a7008ceba96eacbb9127c592cfe89f236ff66025f1ebbb12d96d026da71d" +
	"e2c783ce8f6eab15c305f76eb174ad06bddd86c31496885b745b7223ae7b81cb" +
	"4439477e021043c8fd5c7fedc57305104b9ffaa817624caaf63883a39e4be2c4" +
	"bcda04a45de7be091beea4405750c868726a9347d8a445a16891b0ba33213845" +
	"de17b5f94513e0ae965826f44c5186dbc933b3e6f818640e063567433163246f" +
	"7a26ea2ab2c7789e06e7ad95521c856b71267997dc00b16f81b0b2f211cdd5ac" +
	"ba827de54f1cc160d5e3f049e3085b9d60d1e9664b8c67b759afc08fa20aded6" +
	"473068b515e14d9bfd015f7884e2b01b5e5699dd5d6086419ae8a74bec14d50d" +
	"e9e56dfb5513cf5bce743369c2df9c11ab473605893f2ee08aa84f8783b9ea71" +
	"63c6d47d480535c47f8c5b45db9f9b58e10686bc3b8cf8bdbcab0747fd2d439b" +
	"a0d90ac204ac6198d4140f90c0f931ad07681c2b762ca4519fe9bd9b29e254ee" +
	"2a2f7688eb577b863f501519f35d4fbada04fb1c790199ab6ba025c63e01e00c" +
	"da450b4cdef15fb685edac8abf455c2c63c6665d072215cf6d6330c5b5daa467" +
	"6fd1d2572c2c060c14c6c5b689b9abab06bcd2ff4a67640186f11d1f86e3ae29" +
	"64f5238e2aa87b44421d782f5a594a21eacf95c7bcc74f5b6ebfd50446d84de6" +
	"102c54273d3d02ec6eeafd069b709f40f56d80f372e1d081b642529fb88d417a" +
	"2c3ac12eb7b7e6e43ecdfad0eb12e59fc1314605cf649a7df69a2f8ed19169aa" +
	"5fb5cf3b0bc7b2d6c6e53b7b3f4da12a9e1b1e2c16fd9a1430b314ffab9613d6" +
	"c5e4c42f09a4d0e4d2fcce06335e8ffd727491964c812ed543060bd5764b2e7f" +
	"39277a0d7c5f8367a9aac38ecc9791d95468c38f4b70fbea76ed657729b61d35" +
	"2d79c2a013dec37acb6dac31bb671f96f68bd7141400448d7c74592813419ed6" +
	"b2fdff5aeb577b5980f1ba71e43e200037e722f0d760789c7b2e40524472a045" +
	"d8723cfb43616f0940dea1bf5965e5dee6c2a60c423f061424161e9e397ad38d" +
	"7d9261c437a07d016091315b8f07fa27edaa656210edd052e45f5f9f3e4ee565" +
	"3229306ea09d0c337f05baea8d0d0476001d8b284695689f7abdbf21b1f52f79" +
	"2ff7db462507a05f1d220235fe22fa474bb69a7620a4f24ece5e16e0924be313" +
	"17b5cda316e87b42fd747651dffb094136fa2665289a8d4b4d038974c525199c" +
	"b242d6bc385bdf1d8252266ed8dca73c118036b8e33a15172259d72a22e28504" +
	"da90fe6672b5f69e751f12a970c6478bed9c3502c71f30690e7ef4c99a67adfd" +
	"e9f18a822fa771a7b65e33e462ce0f27981e8de48e24e02a547321b554ef9372"

func TestKeySchedule_Vectors(t *testing.T) {
	a := require.New(t)
	kem := hpke.MLKEM768X25519()
	seed := bytes.Repeat([]byte{0x01}, 32)
	sk, err := kem.DeriveKeyPair(seed)
	a.NoError(err)
	enc, err := hex.DecodeString(vectorEncHex)
	a.NoError(err)
	recip, err := hpke.NewRecipient(
		enc, sk, hpke.HKDFSHA512(), hpke.ExportOnly(),
		[]byte("kamune/2 kex"),
	)
	a.NoError(err)
	ss, err := recip.Export("kamune/2 kex secret", 64)
	a.NoError(err)
	a.Equal(
		"35e13caf96f5ee212abd6af65d1c67f88193355a7b2499db5e1c510aead56a60"+
			"85cf8df40dff2c8178603fcbd0e2f922786f3148600b12251c353d2731a03a58",
		hex.EncodeToString(ss),
	)

	thSH := bytes.Repeat([]byte{0x11}, 64)
	thFinal := bytes.Repeat([]byte{0x22}, 64)
	hs, err := scheduleHS(ss, thSH)
	a.NoError(err)
	a.Equal(
		"fa6cbf226490b3ecd973fc2e0294f28fb5cca534b807f4861c9938bf9086211d",
		hex.EncodeToString(hs.rKey),
	)
	a.Equal(
		"92f5c5413e5aacc4bf8e60cc208ef2b77c47a2de02e55cc63d3a59b64ee622d9",
		hex.EncodeToString(hs.iKey),
	)
	a.Equal(
		"283a067c1ea05c6a8ea972052df529efad6cfded310e385c3ffefcd6a8f26e03"+
			"c61eebc4e83fd8508801e377c4061580aa4cbfca171c7a25baef0396be9af0d7",
		hex.EncodeToString(hs.rFin),
	)
	a.Equal(
		"7c2daec136e8259fee39813492e7e4353e6d7dee496e9e3f6ba55f03816d8aa3"+
			"e29b9251856184a46da050e13e0084146b43817092439a6535611fd478853182",
		hex.EncodeToString(hs.iFin),
	)

	cold, err := masterSecret(hs.hs, bytes.Repeat([]byte{0}, 64))
	a.NoError(err)
	coldBefore := append([]byte(nil), cold...)
	cKey, err := confirmKey(cold)
	a.NoError(err)
	a.Equal(coldBefore, cold)
	a.Equal(
		"3483f9c1ae43bed63abf935c5126f5febf9f182de228e761a6917e6da9563d2a"+
			"7702591050de9b4d59661cfbe92a4b5b3f992ada50ba07b6d710e017557ee04b",
		hex.EncodeToString(cold),
	)
	a.Equal(
		"c3ce0328416a40489465c5d252869551687d6534a9bd08f4f9c2d1c90734f684"+
			"1f17c9e0d236a4e893d871d0984a4014c125337deb59f401a406e93c0893cd8e",
		hex.EncodeToString(cKey),
	)
	resumed, err := masterSecret(hs.hs, bytes.Repeat([]byte{0x02}, 64))
	a.NoError(err)
	a.Equal(
		"bb09a3a9467c93dad7ce1fc9c4e0c53ab9ecfaa17791aadb467ade89e7dd9aa7"+
			"3adbc735595c6989e989b127c05de9de7e85cb52554271f04c38be23847a49a9",
		hex.EncodeToString(resumed),
	)

	sess, err := sessionSecrets(cold, thFinal)
	a.NoError(err)
	a.Equal(
		"10cf316c4a38f39776a13e8607569dd1f0a6349ab3a1c4b1f8333cca96be41d6",
		hex.EncodeToString(sess.iApp),
	)
	a.Equal(
		"46b3da3eac751d1cd3992aa2b3d253e9cb668190738d6c9b7307c1001593f0a0",
		hex.EncodeToString(sess.rApp),
	)
	a.Equal(
		"60e7adc095d67b8c0409ac94e2b659c8ca92e6e36b932026cfaea16ba06c8a82"+
			"b8d00ab256c775039cce051f641443d7e254ca34186c37f13459c8e622d7d3c8",
		hex.EncodeToString(sess.exporter),
	)
	a.Equal(
		"64fc2d1c8403ff9166bc313764705c5786ed5fecc9319df16b15cf2bc163012f"+
			"1faed9b96c0c61dbee8888c9d57436572dfa2f9605fc7989d20ef2e902419776",
		hex.EncodeToString(sess.resNext),
	)
	a.Equal("a56ec3c0c6dd3bf717b137a2063a38", hex.EncodeToString(sess.sid))

	exp, err := exportKeyingMaterial(
		sess.exporter, "kamune/relay-reconnect", nil, 32,
	)
	a.NoError(err)
	a.Equal(
		"8a1f917d55d6fb3170370cdfedaff3e9073a6fb704fca0d9f607cba05b1ab414",
		hex.EncodeToString(exp),
	)
	empty, err := exportKeyingMaterial(
		sess.exporter, "kamune/relay-reconnect", []byte{}, 32,
	)
	a.NoError(err)
	a.Equal(exp, empty)
	otherLabel, err := exportKeyingMaterial(
		sess.exporter, "kamune/other", nil, 32,
	)
	a.NoError(err)
	a.NotEqual(exp, otherLabel)
	otherCtx, err := exportKeyingMaterial(
		sess.exporter, "kamune/relay-reconnect", []byte{1}, 32,
	)
	a.NoError(err)
	a.NotEqual(exp, otherCtx)

	sess2, err := sessionSecrets(resumed, thFinal)
	a.NoError(err)
	exp2, err := exportKeyingMaterial(
		sess2.exporter, "kamune/relay-reconnect", nil, 32,
	)
	a.NoError(err)
	a.NotEqual(exp, exp2)

	_, err = exportKeyingMaterial(sess.exporter, "", nil, 32)
	a.ErrorIs(err, ErrInvalidExport)
	long := string(bytes.Repeat([]byte{'x'}, 201))
	_, err = exportKeyingMaterial(sess.exporter, long, nil, 32)
	a.ErrorIs(err, ErrInvalidExport)
	_, err = exportKeyingMaterial(
		sess.exporter, "kamune/relay-reconnect", nil, 0,
	)
	a.ErrorIs(err, ErrInvalidExport)
	_, err = exportKeyingMaterial(
		sess.exporter, "kamune/relay-reconnect", nil, 16321,
	)
	a.ErrorIs(err, ErrInvalidExport)
}
