package kamune

import (
	"bytes"
	"context"
	"crypto/hpke"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/storage"
)

func TestMITM_SplitKEM(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	ia, ra := hsIdent(t), hsIdent(t)
	iConn, fromI := pipeConns(t)
	toR, rConn := pipeConns(t)
	var seen int
	rCh := startResponder(rConn, responderInput{
		attest: ra, store: store, name: "bob", resumeEnabled: true,
		verify: func(context.Context, *storage.Storage, VerifyRequest) error {
			seen++
			return nil
		},
	})
	go splitKEM(fromI, toR)
	gi := <-startInitiator(iConn, initiatorInput{
		attest: ia, store: store, name: "ada",
		verify: acceptVerify(nil, nil),
	})
	a.ErrorIs(gi.err, ErrInvalidSignature)
	_ = toR.Close()
	gr := <-rCh
	a.Error(gr.err)
	a.Zero(seen)
}

func splitKEM(fromI, toR Conn) {
	chI, err := fromI.ReadBytes()
	if err != nil {
		return
	}
	sk, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		return
	}
	nonce, tag, err := randomHello()
	if err != nil {
		return
	}
	chP, err := writeClientHello(nil, nonce, tag, sk.PublicKey().Bytes())
	if err != nil {
		return
	}
	if err = toR.WriteBytes(chP); err != nil {
		return
	}
	shR, err := toR.ReadBytes()
	if err != nil {
		return
	}
	raR, err := toR.ReadBytes()
	if err != nil {
		return
	}
	_, enc, err := parseServerHello(shR)
	if err != nil {
		return
	}
	recip, err := hpke.NewRecipient(
		enc, sk, hpke.HKDFSHA512(), hpke.ExportOnly(), []byte(kexInfo),
	)
	if err != nil {
		return
	}
	ss, err := recip.Export(kexExport, hashLen)
	if err != nil {
		return
	}
	var th transcript
	th.add(0x01, chP)
	th.add(0x02, shR)
	hsR, err := scheduleHS(ss, th.sum())
	if err != nil {
		return
	}
	plain, err := openHS(hsR.rKey, raR, frameResponderAuth)
	if err != nil {
		return
	}
	_, _, pkI, err := parseClientHello(chI)
	if err != nil {
		return
	}
	pub, err := hpke.MLKEM768X25519().NewPublicKey(pkI)
	if err != nil {
		return
	}
	enc2, sender, err := hpke.NewSender(
		pub, hpke.HKDFSHA512(), hpke.ExportOnly(), []byte(kexInfo),
	)
	if err != nil {
		return
	}
	ss2, err := sender.Export(kexExport, hashLen)
	if err != nil {
		return
	}
	nonce2, _, err := randomHello()
	if err != nil {
		return
	}
	shP, err := writeServerHello(nil, nonce2, enc2)
	if err != nil {
		return
	}
	var thI transcript
	thI.add(0x01, chI)
	thI.add(0x02, shP)
	hsI, err := scheduleHS(ss2, thI.sum())
	if err != nil {
		return
	}
	sealed, err := sealHS(hsI.rKey, plain, protocolVersion, frameResponderAuth)
	if err != nil {
		return
	}
	if err = fromI.WriteBytes(shP); err != nil {
		return
	}
	_ = fromI.WriteBytes(sealed)
}

func TestMITM_OwnKey_Pinned(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	ia, realID, atk := hsIdent(t), hsIdent(t), hsIdent(t)
	ic, rc := pipeConns(t)
	iw := &wireConn{Conn: ic}
	iCh := startInitiator(iw, initiatorInput{
		attest: ia, store: store, name: "ada",
		pin:    realID.MarshalPublicKey(),
		verify: acceptVerify(nil, nil),
	})
	rCh := startResponder(rc, responderInput{
		attest: atk, store: store, name: "mallory", resumeEnabled: true,
		verify: acceptVerify(nil, nil),
	})
	gi, gr := <-iCh, <-rCh
	a.ErrorIs(gi.err, ErrPeerKeyMismatch)
	a.Error(gr.err)
	for _, n := range iw.lengths() {
		a.NotEqual(initiatorAuthSize, n)
	}
}

func TestMITM_OwnKey_Unpinned_Rejected(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	ia, atk := hsIdent(t), hsIdent(t)
	ic, rc := pipeConns(t)
	iw := &wireConn{Conn: ic}
	iCh := startInitiator(iw, initiatorInput{
		attest: ia, store: store, name: "ada",
		verify: func(context.Context, *storage.Storage, VerifyRequest) error {
			return errors.New("reject")
		},
	})
	rCh := startResponder(rc, responderInput{
		attest: atk, store: store, name: "mallory", resumeEnabled: true,
		verify: acceptVerify(nil, nil),
	})
	gi, gr := <-iCh, <-rCh
	a.ErrorIs(gi.err, ErrVerificationFailed)
	a.Error(gr.err)
	for _, n := range iw.lengths() {
		a.NotEqual(initiatorAuthSize, n)
	}
}

func TestMITM_ProbeResponder(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	ia, ra := hsIdent(t), hsIdent(t)
	ic, rc := pipeConns(t)
	rw := &wireConn{Conn: rc}
	name, ver := "secret-name", "1.2.3"
	iCh := startInitiator(ic, initiatorInput{
		attest: ia, store: store, name: "ada", version: ver,
		verify: acceptVerify(nil, nil),
	})
	rCh := startResponder(rw, responderInput{
		attest: ra, store: store, name: name, version: ver,
		resumeEnabled: true, verify: acceptVerify(nil, nil),
	})
	gi, gr := <-iCh, <-rCh
	a.NoError(gi.err)
	a.NoError(gr.err)
	a.Equal(ra.MarshalPublicKey(), gi.tr.RemotePeer().PublicKey)
	for _, n := range rw.frames() {
		a.False(bytes.Contains(n, []byte(name)))
		a.False(bytes.Contains(n, []byte(ver)))
	}
}

func TestReplay_InitiatorAuth(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, _, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	before, err := store.GetResumption(sid, storage.ResumeRoleResponder)
	a.NoError(err)
	li, lr := pipeConns(t)
	iw, rw := &wireConn{Conn: li}, &wireConn{Conn: lr}
	gi, gr := resumeBoth(t, store, ia, ra, "", nil, nil, nil, iw, rw)
	a.NoError(gi.err)
	a.NoError(gr.err)
	var f1, f3 []byte
	for _, frame := range iw.frames() {
		switch len(frame) {
		case clientHelloSize:
			f1 = frame
		case initiatorAuthSize:
			f3 = frame
		}
	}
	a.NotNil(f1)
	a.NotNil(f3)
	a.NoError(gi.tr.CloseAbort())
	a.NoError(gr.tr.CloseAbort())
	var seen int
	ic2, rc2 := pipeConns(t)
	go func() {
		_ = ic2.WriteBytes(f1)
		_, _ = ic2.ReadBytes()
		_, _ = ic2.ReadBytes()
		_ = ic2.WriteBytes(f3)
	}()
	gr = <-startResponder(rc2, responderInput{
		attest: ra, store: store, name: "bob", resumeEnabled: true,
		verify: func(context.Context, *storage.Storage, VerifyRequest) error {
			seen++
			return nil
		},
	})
	a.ErrorIs(gr.err, ErrVerificationFailed)
	a.Zero(seen)
	after, err := store.GetResumption(sid, storage.ResumeRoleResponder)
	a.NoError(err)
	a.Equal(before.Generation, after.Generation)
	a.Equal(before.Current, after.Current)
}

func TestReplay_ResponderAuth(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	ia, ra := hsIdent(t), hsIdent(t)
	li, lr := pipeConns(t)
	rw := &wireConn{Conn: lr}
	gi, gr := resumeBoth(t, store, ia, ra, "", nil, nil, nil, li, rw)
	a.NoError(gi.err)
	a.NoError(gr.err)
	var sh, raFrame []byte
	for _, frame := range rw.frames() {
		switch len(frame) {
		case serverHelloSize:
			sh = bytes.Clone(frame)
		case responderAuthSize:
			raFrame = bytes.Clone(frame)
		}
	}
	a.NoError(gi.tr.CloseAbort())
	a.NoError(gr.tr.CloseAbort())
	ic, sink := pipeConns(t)
	go func() {
		_, _ = sink.ReadBytes()
		_ = sink.WriteBytes(sh)
		_ = sink.WriteBytes(raFrame)
	}()
	got := <-startInitiator(ic, initiatorInput{
		attest: ia, store: store, name: "ada",
		verify: acceptVerify(nil, nil),
	})
	a.Error(got.err)
	a.True(errors.Is(got.err, ErrVerificationFailed) ||
		errors.Is(got.err, ErrInvalidSignature))
}

func TestReplay_ResumeOffer(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	it, rt, ia, ra := coldPair(t, store, nil)
	sid := it.SessionID()
	remember(t, store, ia)
	remember(t, store, ra)
	a.NoError(it.CloseAbort())
	a.NoError(rt.CloseAbort())
	li, lr := pipeConns(t)
	iw := &wireConn{Conn: li}
	gi, gr := resumeBoth(t, store, ia, ra, sid, nil, nil, nil, iw, lr)
	a.NoError(gi.err)
	a.NoError(gr.err)
	var f1, f3 []byte
	for _, frame := range iw.frames() {
		switch len(frame) {
		case clientHelloSize:
			f1 = bytes.Clone(frame)
		case initiatorAuthSize:
			f3 = bytes.Clone(frame)
		}
	}
	row, err := store.GetResumption(sid, storage.ResumeRoleResponder)
	a.NoError(err)
	a.NoError(gi.tr.CloseAbort())
	a.NoError(gr.tr.CloseAbort())
	ic, rc := pipeConns(t)
	go func() {
		_ = ic.WriteBytes(f1)
		_, _ = ic.ReadBytes()
		_, _ = ic.ReadBytes()
		_ = ic.WriteBytes(f3)
	}()
	gr = <-startResponder(rc, responderInput{
		attest: ra, store: store, name: "bob", resumeEnabled: true,
		verify: acceptVerify(nil, nil),
	})
	a.Error(gr.err)
	after, err := store.GetResumption(sid, storage.ResumeRoleResponder)
	a.NoError(err)
	a.Equal(row.Generation, after.Generation)
	a.Equal(row.Current, after.Current)
}

func TestHandshake_BadHello(t *testing.T) {
	validPK := func() []byte {
		sk, err := hpke.MLKEM768X25519().GenerateKey()
		require.New(t).NoError(err)
		return sk.PublicKey().Bytes()
	}
	pk := validPK()
	nonce := bytes.Repeat([]byte{1}, helloNonceLen)
	tag := bytes.Repeat([]byte{2}, helloNonceLen)
	good := append([]byte{protocolVersion, frameClientHello}, nonce...)
	good = append(good, tag...)
	good = append(good, pk...)

	cases := []struct {
		name  string
		frame []byte
		want  error
	}{
		{"version", func() []byte {
			f := bytes.Clone(good)
			f[0] = 0x01
			return f
		}(), ErrUnsupportedProtocol},
		{"type", func() []byte {
			f := bytes.Clone(good)
			f[1] = 0x09
			return f
		}(), ErrInvalidHandshake},
		{"length", good[:10], ErrInvalidHandshake},
		{"pk", func() []byte {
			f := bytes.Clone(good)
			for i := 66; i < len(f); i++ {
				f[i] = 0xff
			}
			return f
		}(), ErrInvalidHandshake},
		{"low order", func() []byte {
			f := bytes.Clone(good)
			for i := 66; i < len(f); i++ {
				f[i] = 0
			}
			return f
		}(), ErrInvalidHandshake},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			store := openStore(t)
			ra := hsIdent(t)
			ic, rc := pipeConns(t)
			rw := &wireConn{Conn: rc}
			go func() { _ = ic.WriteBytes(tc.frame) }()
			gr := <-startResponder(rw, responderInput{
				attest: ra, store: store, name: "bob",
				resumeEnabled: true, verify: acceptVerify(nil, nil),
			})
			a.ErrorIs(gr.err, tc.want)
			a.Empty(rw.lengths())
		})
	}
}

func TestHandshake_BadIdentity(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		a := require.New(t)
		err := scriptConfirm(t, func(plain []byte) {
			plain[0] = 9
		})
		a.ErrorIs(err, ErrInvalidHandshake)
	})
	t.Run("padding", func(t *testing.T) {
		a := require.New(t)
		err := scriptInitiatorAuth(t, func(key []byte) []byte {
			id := initiatorBlock{
				Key: key, Name: []byte("ada"), Version: []byte("0.8.0"),
			}
			block, err := encodeIdentity(id)
			require.New(t).NoError(err)
			plain := make([]byte, initiatorAuthPlain)
			copy(plain, block)
			plain[len(plain)-1] = 1
			return plain
		})
		a.ErrorIs(err, ErrInvalidHandshake)
	})
	t.Run("small order", func(t *testing.T) {
		a := require.New(t)
		err := scriptInitiatorAuth(t, func(key []byte) []byte {
			bad := append([]byte{}, pkixPrefix...)
			bad = append(bad, make([]byte, 32)...)
			return identityPlain(t, bad, []byte("ada"), []byte("0.8.0"), nil)
		})
		a.ErrorIs(err, ErrInvalidHandshake)
	})
	t.Run("prefix", func(t *testing.T) {
		a := require.New(t)
		err := scriptInitiatorAuth(t, func([]byte) []byte {
			return identityPlain(t, bytes.Repeat([]byte{1}, pkixLen),
				[]byte("ada"), []byte("0.8.0"), nil)
		})
		a.ErrorIs(err, ErrInvalidHandshake)
	})
	t.Run("name", func(t *testing.T) {
		a := require.New(t)
		err := scriptInitiatorAuth(t, func(key []byte) []byte {
			return identityPlain(t, key, []byte{'\n'}, []byte("0.8.0"), nil)
		})
		a.ErrorIs(err, ErrInvalidPeerName)
		a.NotErrorIs(err, ErrInvalidHandshake)
	})
	t.Run("version", func(t *testing.T) {
		a := require.New(t)
		err := scriptInitiatorAuth(t, func(key []byte) []byte {
			return identityPlain(t, key, []byte("ada"),
				bytes.Repeat([]byte{'1'}, 33), nil)
		})
		a.ErrorIs(err, ErrInvalidHandshake)
	})
	t.Run("sid", func(t *testing.T) {
		a := require.New(t)
		err := scriptInitiatorAuth(t, func(key []byte) []byte {
			return identityPlain(t, key, []byte("ada"), []byte("0.8.0"),
				[]byte("ABCDE"))
		})
		a.ErrorIs(err, ErrInvalidHandshake)
	})
}

func identityPlain(t *testing.T, key, name, version, sid []byte) []byte {
	t.Helper()
	out := make([]byte, initiatorAuthPlain)
	n := copy(out, key)
	out[n] = byte(len(name))
	n++
	n += copy(out[n:], name)
	out[n] = byte(len(version))
	n++
	n += copy(out[n:], version)
	out[n] = byte(len(sid))
	n++
	copy(out[n:], sid)
	return out
}

func scriptInitiatorAuth(t *testing.T, plainFn func(key []byte) []byte) error {
	t.Helper()
	store := openStore(t)
	ra := hsIdent(t)
	ic, rc := pipeConns(t)
	errc := make(chan error, 1)
	go func() {
		_, err := runResponder(context.Background(), rc, responderInput{
			attest: ra, store: store, name: "bob", resumeEnabled: true,
			verify: acceptVerify(nil, nil),
		})
		errc <- err
	}()
	sk, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		return err
	}
	nonce, tag, err := randomHello()
	if err != nil {
		return err
	}
	ch, err := writeClientHello(nil, nonce, tag, sk.PublicKey().Bytes())
	if err != nil {
		return err
	}
	if err = ic.WriteBytes(ch); err != nil {
		return err
	}
	sh, err := ic.ReadBytes()
	if err != nil {
		return err
	}
	raFrame, err := ic.ReadBytes()
	if err != nil {
		return err
	}
	_, enc, err := parseServerHello(sh)
	if err != nil {
		return err
	}
	recip, err := hpke.NewRecipient(
		enc, sk, hpke.HKDFSHA512(), hpke.ExportOnly(), []byte(kexInfo),
	)
	if err != nil {
		return err
	}
	ss, err := recip.Export(kexExport, hashLen)
	if err != nil {
		return err
	}
	var th transcript
	th.add(0x01, ch)
	th.add(0x02, sh)
	hs, err := scheduleHS(ss, th.sum())
	if err != nil {
		return err
	}
	if _, err = openHS(hs.rKey, raFrame, frameResponderAuth); err != nil {
		return err
	}
	plain := plainFn(ra.MarshalPublicKey())
	sealed, err := sealHS(hs.iKey, plain, protocolVersion, frameInitiatorAuth)
	if err != nil {
		return err
	}
	if err = ic.WriteBytes(sealed); err != nil {
		return err
	}
	return <-errc
}

func scriptConfirm(t *testing.T, mutate func([]byte)) error {
	t.Helper()
	a := require.New(t)
	store := openStore(t)
	ia, ra := hsIdent(t), hsIdent(t)
	ic, rc := pipeConns(t)
	errc := make(chan error, 1)
	go func() {
		_, err := runInitiator(context.Background(), ic, initiatorInput{
			attest: ia, store: store, name: "ada",
			verify: acceptVerify(nil, nil),
		})
		errc <- err
	}()
	ch, err := rc.ReadBytes()
	a.NoError(err)
	_, _, pk, err := parseClientHello(ch)
	a.NoError(err)
	pub, err := hpke.MLKEM768X25519().NewPublicKey(pk)
	a.NoError(err)
	enc, sender, err := hpke.NewSender(
		pub, hpke.HKDFSHA512(), hpke.ExportOnly(), []byte(kexInfo),
	)
	a.NoError(err)
	ss, err := sender.Export(kexExport, hashLen)
	a.NoError(err)
	nonce, _, err := randomHello()
	a.NoError(err)
	sh, err := writeServerHello(nil, nonce, enc)
	a.NoError(err)
	var th transcript
	th.add(0x01, ch)
	th.add(0x02, sh)
	hs, err := scheduleHS(ss, th.sum())
	a.NoError(err)
	local := ra.MarshalPublicKey()
	th.add(0x10, local)
	sigR, err := ra.Sign(signedTH(attest.ContextResponderHandshake, th.sum()))
	a.NoError(err)
	th.add(0x11, sigR)
	finR := macSHA512(hs.rFin, th.sum())
	th.add(0x12, finR)
	raw, err := encodeResponderAuth(local, sigR, finR)
	a.NoError(err)
	sealed, err := sealHS(hs.rKey, raw, protocolVersion, frameResponderAuth)
	a.NoError(err)
	a.NoError(rc.WriteBytes(sh))
	a.NoError(rc.WriteBytes(sealed))
	iaFrame, err := rc.ReadBytes()
	a.NoError(err)
	iplain, err := openHS(hs.iKey, iaFrame, frameInitiatorAuth)
	a.NoError(err)
	id, _, sigI, finI, err := parseInitiatorAuth(iplain)
	a.NoError(err)
	block, err := encodeIdentity(id)
	a.NoError(err)
	th.add(0x20, block)
	th.add(0x22, sigI)
	th.add(0x23, finI)
	body, err := encodeConfirmBody(confirmCold, 0, "bob", "0.8.0")
	a.NoError(err)
	plain := make([]byte, confirmPlain)
	copy(plain, body)
	mutate(plain)
	th.add(0x30, plain[:len(body)])
	master, err := masterSecret(hs.hs, pskOrZero(nil))
	a.NoError(err)
	cKey, err := confirmKey(master)
	a.NoError(err)
	copy(plain[len(body):], macSHA512(cKey, th.sum()))
	out, err := sealHS(hs.rKey, plain, protocolVersion, frameConfirm)
	a.NoError(err)
	a.NoError(rc.WriteBytes(out))
	return <-errc
}

func TestHandshake_ReflectedSignature(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	ra := hsIdent(t)
	ic, rc := pipeConns(t)
	errc := make(chan error, 1)
	go func() {
		_, e := runResponder(context.Background(), rc, responderInput{
			attest: ra, store: store, name: "bob", resumeEnabled: true,
			verify: acceptVerify(nil, nil),
		})
		errc <- e
	}()
	sk, err := hpke.MLKEM768X25519().GenerateKey()
	a.NoError(err)
	nonce, tag, err := randomHello()
	a.NoError(err)
	ch, err := writeClientHello(nil, nonce, tag, sk.PublicKey().Bytes())
	a.NoError(err)
	a.NoError(ic.WriteBytes(ch))
	sh, err := ic.ReadBytes()
	a.NoError(err)
	raFrame, err := ic.ReadBytes()
	a.NoError(err)
	_, enc, err := parseServerHello(sh)
	a.NoError(err)
	recip, err := hpke.NewRecipient(
		enc, sk, hpke.HKDFSHA512(), hpke.ExportOnly(), []byte(kexInfo),
	)
	a.NoError(err)
	ss, err := recip.Export(kexExport, hashLen)
	a.NoError(err)
	var th transcript
	th.add(0x01, ch)
	th.add(0x02, sh)
	hs, err := scheduleHS(ss, th.sum())
	a.NoError(err)
	plain, err := openHS(hs.rKey, raFrame, frameResponderAuth)
	a.NoError(err)
	_, sigR, finR, err := parseResponderAuth(plain)
	a.NoError(err)
	id := initiatorBlock{
		Key:     hsIdent(t).MarshalPublicKey(),
		Name:    []byte("ada"),
		Version: []byte("0.8.0"),
	}
	raw, err := encodeInitiatorAuth(id, nil, sigR, finR)
	a.NoError(err)
	sealed, err := sealHS(hs.iKey, raw, protocolVersion, frameInitiatorAuth)
	a.NoError(err)
	a.NoError(ic.WriteBytes(sealed))
	a.ErrorIs(<-errc, ErrInvalidSignature)
}

func TestPeerConstraint_RejectsBeforeVerifier(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	ia, ra := hsIdent(t), hsIdent(t)
	other := hsIdent(t)
	ic, rc := pipeConns(t)
	iw := &wireConn{Conn: ic}
	var seen int
	iCh := startInitiator(ExpectPeer(iw, other.MarshalPublicKey()), initiatorInput{
		attest: ia, store: store, name: "ada",
		verify: func(context.Context, *storage.Storage, VerifyRequest) error {
			seen++
			return nil
		},
	})
	rCh := startResponder(rc, responderInput{
		attest: ra, store: store, name: "bob", resumeEnabled: true,
		verify: func(context.Context, *storage.Storage, VerifyRequest) error {
			seen++
			return nil
		},
	})
	gi, gr := <-iCh, <-rCh
	a.ErrorIs(gi.err, ErrPeerKeyMismatch)
	a.Error(gr.err)
	a.Zero(seen)
	for _, n := range iw.lengths() {
		a.NotEqual(initiatorAuthSize, n)
		a.NotEqual(confirmFrameSize, n)
	}
}

func TestPeerConstraint_ResponderRejectsBeforeConfirm(t *testing.T) {
	a := require.New(t)
	store := openStore(t)
	ia, ra := hsIdent(t), hsIdent(t)
	other := hsIdent(t)
	ic, rc := pipeConns(t)
	rw := &wireConn{Conn: rc}
	var seen int
	iCh := startInitiator(ic, initiatorInput{
		attest: ia, store: store, name: "ada",
		verify: acceptVerify(nil, nil),
	})
	rCh := startResponder(
		ExpectPeer(rw, other.MarshalPublicKey()),
		responderInput{
			attest: ra, store: store, name: "bob", resumeEnabled: true,
			verify: func(
				context.Context, *storage.Storage, VerifyRequest,
			) error {
				seen++
				return nil
			},
		},
	)
	gi, gr := <-iCh, <-rCh
	a.Error(gi.err)
	a.ErrorIs(gr.err, ErrPeerKeyMismatch)
	a.Zero(seen)
	for _, n := range rw.lengths() {
		a.NotEqual(confirmFrameSize, n)
	}
}
