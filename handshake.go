package kamune

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/kamune-org/kamune/internal/clock"
	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/storage"
)

const (
	// defaultHandshakeTimeout bounds the network steps of a handshake.
	defaultHandshakeTimeout = 30 * time.Second

	// defaultVerifyTimeout bounds how long a RemoteVerifier may take. It is
	// longer than the two-minute fingerprint prompt of the bundled clients,
	// so their own timeout fires first.
	defaultVerifyTimeout = 150 * time.Second
)

type handshakeOpts struct {
	remoteVerifier RemoteVerifier
	pin            []byte
	sessionID      string
	timeout        time.Duration
	// verifyTimeout bounds the local verifier, and is the time allowed for
	// the remote peer's verifier while waiting for its answer.
	verifyTimeout time.Duration
	// noPersistence keeps session state out of storage. See
	// [ServeWithoutPersistence] and [DialWithoutPersistence].
	noPersistence bool
	resumeOnly    bool
}

const kexInfo = "kamune/2 kex"
const kexExport = "kamune/2 kex secret"

// initiatorInput is what runInitiator needs besides the connection.
type initiatorInput struct {
	attest        *attest.Attest
	store         *storage.Storage
	verify        verifyFunc
	pin           []byte
	resumeSID     string
	resumeOnly    bool
	noPersistence bool
	verifyTimeout time.Duration
	name          string
	version       string
	clock         clock.Clock
}

// responderInput is what runResponder needs besides the connection.
type responderInput struct {
	attest        *attest.Attest
	store         *storage.Storage
	verify        verifyFunc
	resumeEnabled bool
	noPersistence bool
	verifyTimeout time.Duration
	introTimeout  time.Duration
	name          string
	version       string
	clock         clock.Clock
	onHello       func() error
	onAuth        func() error
	// dropped reports that admission closed this connection to make room.
	dropped func() bool
}

type resumeDecision struct {
	resumed bool
	used    []byte
	row     *storage.Resumption
}

func runInitiator(
	ctx context.Context, cn Conn, in initiatorInput,
) (*Transport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	stop := context.AfterFunc(ctx, func() { _ = cn.Close() })
	defer stop()

	var offer *storage.Resumption
	if in.resumeSID != "" {
		unlock, ok := tryResumeLock(in.store, in.resumeSID)
		if !ok {
			return failHS(cn, ErrResumeInProgress)
		}
		defer unlock()
		row, err := loadOffer(in)
		if err != nil {
			return failHS(cn, err)
		}
		offer = row
		in.pin = row.PeerKey
	}

	if err := cn.SetDeadline(time.Now().Add(defaultHandshakeTimeout)); err != nil {
		return failHS(cn, err)
	}
	sk, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		return failHS(cn, fmt.Errorf("ephemeral key: %w", err))
	}
	nonce, tag, err := randomHello()
	if err != nil {
		return failHS(cn, err)
	}
	ch, err := writeClientHello(nil, nonce, tag, sk.PublicKey().Bytes())
	if err != nil {
		return failHS(cn, err)
	}
	var th transcript
	th.add(0x01, ch)
	if err = writeHS(ctx, cn, ch); err != nil {
		return failHS(cn, err)
	}

	sh, err := readHS(ctx, cn)
	if err != nil {
		return failHS(cn, err)
	}
	_, enc, err := parseServerHello(sh)
	if err != nil {
		return failHS(cn, err)
	}
	th.add(0x02, sh)
	recip, err := hpke.NewRecipient(
		enc, sk, hpke.HKDFSHA512(), hpke.ExportOnly(), []byte(kexInfo),
	)
	if err != nil {
		return failHS(cn, ErrVerificationFailed)
	}
	ss, err := recip.Export(kexExport, hashLen)
	if err != nil {
		return failHS(cn, fmt.Errorf("%w: %w", ErrInvalidHandshake, err))
	}
	hs, err := scheduleHS(ss, th.sum())
	if err != nil {
		return failHS(cn, err)
	}

	ra, err := readHS(ctx, cn)
	if err != nil {
		return failHS(cn, err)
	}
	plain, err := openHS(hs.rKey, ra, frameResponderAuth)
	if err != nil {
		return failHS(cn, err)
	}
	keyR, sigR, finR, err := parseResponderAuth(plain)
	if err != nil {
		return failHS(cn, err)
	}
	local := in.attest.MarshalPublicKey()
	if bytes.Equal(keyR, local) {
		return failHS(cn, ErrSelfConnection)
	}
	pinned := false
	if len(in.pin) > 0 {
		if !bytes.Equal(keyR, in.pin) {
			return failHS(cn, ErrPeerKeyMismatch)
		}
		pinned = true
	}
	th.add(0x10, keyR)
	if !attest.Verify(
		keyR, signedTH(attest.ContextResponderHandshake, th.sum()), sigR,
	) {
		return failHS(cn, ErrInvalidSignature)
	}
	th.add(0x11, sigR)
	if !hmac.Equal(finR, macSHA512(hs.rFin, th.sum())) {
		return failHS(cn, ErrVerificationFailed)
	}
	th.add(0x12, finR)
	if ran, ok := allowPeer(cn, keyR); ran && !ok {
		return failHS(cn, ErrPeerKeyMismatch)
	} else if ran {
		pinned = true
	}

	if err = liftVerify(cn, in.verifyTimeout); err != nil {
		return failHS(cn, err)
	}
	err = runVerifier(ctx, in.verifyTimeout, in.verify, in.store, VerifyRequest{
		Peer:           &storage.Peer{PublicKey: bytes.Clone(keyR)},
		LocalPublicKey: local,
		SessionID:      in.resumeSID,
		Role:           RoleInitiator,
		Pinned:         pinned,
		ResumeOffered:  offer != nil,
	})
	if err != nil {
		if ctx.Err() != nil {
			return failHS(cn, fmt.Errorf("%w: %w", ErrVerificationFailed, ctx.Err()))
		}
		return failHS(cn, fmt.Errorf("%w: %w", ErrVerificationFailed, err))
	}
	if err = cn.SetDeadline(time.Now().Add(
		defaultHandshakeTimeout + verifyTimeoutOrDefault(in.verifyTimeout),
	)); err != nil {
		return failHS(cn, err)
	}

	id := initiatorBlock{
		Key: local, Name: []byte(in.name), Version: []byte(versionOf(in.version)),
	}
	var binder []byte
	if offer != nil {
		id.ResumeSID = []byte(in.resumeSID)
	}
	block, err := encodeIdentity(id)
	if err != nil {
		return failHS(cn, err)
	}
	th.add(0x20, block)
	thIID := th.sum()
	if offer != nil {
		bk, err := binderKey(offer.Current)
		if err != nil {
			return failHS(cn, err)
		}
		binder = macSHA512(bk, thIID)
		th.add(0x21, binder)
	}
	sigI, err := in.attest.Sign(
		signedTH(attest.ContextInitiatorHandshake, th.sum()),
	)
	if err != nil {
		return failHS(cn, err)
	}
	th.add(0x22, sigI)
	finI := macSHA512(hs.iFin, th.sum())
	th.add(0x23, finI)
	ia, err := encodeInitiatorAuth(id, binder, sigI, finI)
	if err != nil {
		return failHS(cn, err)
	}
	sealed, err := sealHS(hs.iKey, ia, protocolVersion, frameInitiatorAuth)
	if err != nil {
		return failHS(cn, err)
	}
	if err = writeHS(ctx, cn, sealed); err != nil {
		return failHS(cn, err)
	}

	cf, err := readHS(ctx, cn)
	if err != nil {
		return failHS(cn, err)
	}
	cplain, err := openHS(hs.rKey, cf, frameConfirm)
	if err != nil {
		return failHS(cn, err)
	}
	status, reason, nameR, verR, finC, err := parseConfirm(cplain)
	if err != nil {
		return failHS(cn, err)
	}
	var psk []byte
	if status == confirmResumed && offer != nil {
		psk, err = resPSK(offer.Current)
		if err != nil {
			return failHS(cn, err)
		}
	}
	body, err := encodeConfirmBody(status, reason, nameR, verR)
	if err != nil {
		return failHS(cn, err)
	}
	master, err := masterSecret(hs.hs, pskOrZero(psk))
	if err != nil {
		return failHS(cn, err)
	}
	cKey, err := confirmKey(master)
	if err != nil {
		return failHS(cn, err)
	}
	th.add(0x30, body)
	if !hmac.Equal(finC, macSHA512(cKey, th.sum())) {
		return failHS(cn, ErrVerificationFailed)
	}
	th.add(0x31, finC)
	if err = checkConfirmStatus(status, reason, nameR, verR); err != nil {
		return failHS(cn, err)
	}
	switch status {
	case confirmRejected:
		if offer != nil && reason == reasonVerifier {
			_ = in.store.DeleteResumption(
				in.resumeSID, storage.ResumeRoleInitiator, offer.Generation,
			)
		}
		if reason == reasonVersion {
			return failHS(cn, fmt.Errorf(
				"%w: %w", ErrHandshakeRejected, ErrVersionMismatch,
			))
		}
		return failHS(cn, ErrHandshakeRejected)
	case confirmResumed:
		if offer == nil {
			return failHS(cn, fmt.Errorf(
				"%w: resumed without an offer", ErrInvalidHandshake,
			))
		}
	}
	if err = ValidatePeerName(nameR); err != nil {
		return failHS(cn, err)
	}
	if err = checkVersion(versionOf(in.version), verR); err != nil {
		return failHS(cn, err)
	}
	if status == confirmCold && in.resumeOnly && offer != nil {
		return failHS(cn, ErrResumeRefused)
	}
	sess, err := sessionSecrets(master, th.sum())
	if err != nil {
		return failHS(cn, err)
	}
	sid := base32.StdEncoding.EncodeToString(sess.sid)
	resumed := status == confirmResumed
	if resumed {
		sid = in.resumeSID
	}
	gen, err := commitInitiator(in, offer, sid, keyR, sess.resNext, resumed)
	if err != nil {
		return failHS(cn, err)
	}
	_ = cn.SetDeadline(time.Time{})
	return newHSTransport(
		cn, in.attest, in.store, in.clock, sid, nameR, verR, keyR,
		sess.iApp, sess.rApp, sess.exporter, gen,
		storage.ResumeRoleInitiator, resumed, in.noPersistence,
	)
}

func runResponder(
	ctx context.Context, cn Conn, in responderInput,
) (*Transport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	stop := context.AfterFunc(ctx, func() { _ = cn.Close() })
	defer stop()
	helloWait := in.introTimeout
	if helloWait <= 0 {
		helloWait = defaultIntroTimeout
	}
	if err := cn.SetDeadline(time.Now().Add(helloWait)); err != nil {
		return failHS(cn, err)
	}
	ch, err := readHS(ctx, cn)
	if err != nil {
		return failHS(cn, err)
	}
	_, _, pk, err := parseClientHello(ch)
	if err != nil {
		return failHS(cn, err)
	}
	if in.onHello != nil {
		if err = in.onHello(); err != nil {
			return failHS(cn, err)
		}
	}
	var th transcript
	th.add(0x01, ch)
	pub, err := hpke.MLKEM768X25519().NewPublicKey(pk)
	if err != nil {
		return failHS(cn, fmt.Errorf("%w: %w", ErrInvalidHandshake, err))
	}
	enc, sender, err := hpke.NewSender(
		pub, hpke.HKDFSHA512(), hpke.ExportOnly(), []byte(kexInfo),
	)
	if err != nil {
		return failHS(cn, fmt.Errorf("%w: %w", ErrInvalidHandshake, err))
	}
	ss, err := sender.Export(kexExport, hashLen)
	if err != nil {
		return failHS(cn, fmt.Errorf("%w: %w", ErrInvalidHandshake, err))
	}
	nonce, _, err := randomHello()
	if err != nil {
		return failHS(cn, err)
	}
	sh, err := writeServerHello(nil, nonce, enc)
	if err != nil {
		return failHS(cn, err)
	}
	th.add(0x02, sh)
	hs, err := scheduleHS(ss, th.sum())
	if err != nil {
		return failHS(cn, err)
	}
	if in.dropped != nil && in.dropped() {
		return failHS(cn, ErrConnClosed)
	}
	local := in.attest.MarshalPublicKey()
	th.add(0x10, local)
	sigR, err := in.attest.Sign(
		signedTH(attest.ContextResponderHandshake, th.sum()),
	)
	if err != nil {
		return failHS(cn, err)
	}
	th.add(0x11, sigR)
	finR := macSHA512(hs.rFin, th.sum())
	th.add(0x12, finR)
	ra, err := encodeResponderAuth(local, sigR, finR)
	if err != nil {
		return failHS(cn, err)
	}
	sealed, err := sealHS(hs.rKey, ra, protocolVersion, frameResponderAuth)
	if err != nil {
		return failHS(cn, err)
	}
	if err = writeHS(ctx, cn, sh); err != nil {
		return failHS(cn, err)
	}
	if err = writeHS(ctx, cn, sealed); err != nil {
		return failHS(cn, err)
	}
	if err = cn.SetDeadline(time.Now().Add(
		defaultHandshakeTimeout + verifyTimeoutOrDefault(in.verifyTimeout),
	)); err != nil {
		return failHS(cn, err)
	}

	ia, err := readHS(ctx, cn)
	if err != nil {
		return failHS(cn, err)
	}
	iplain, err := openHS(hs.iKey, ia, frameInitiatorAuth)
	if err != nil {
		return failHS(cn, err)
	}
	id, binder, sigI, finI, err := parseInitiatorAuth(iplain)
	if err != nil {
		return failHS(cn, err)
	}
	if bytes.Equal(id.Key, local) {
		return failHS(cn, ErrSelfConnection)
	}
	block, err := encodeIdentity(id)
	if err != nil {
		return failHS(cn, err)
	}
	th.add(0x20, block)
	thIID := th.sum()
	if len(binder) > 0 {
		th.add(0x21, binder)
	}
	if !attest.Verify(
		id.Key, signedTH(attest.ContextInitiatorHandshake, th.sum()), sigI,
	) {
		return failHS(cn, ErrInvalidSignature)
	}
	th.add(0x22, sigI)
	if !hmac.Equal(finI, macSHA512(hs.iFin, th.sum())) {
		return failHS(cn, ErrVerificationFailed)
	}
	th.add(0x23, finI)
	if in.onAuth != nil {
		if err = in.onAuth(); err != nil {
			return failHS(cn, err)
		}
	}
	pinned := false
	if ran, ok := allowPeer(cn, id.Key); ran && !ok {
		return failHS(cn, ErrPeerKeyMismatch)
	} else if ran {
		pinned = true
	}
	if err = checkVersion(
		versionOf(in.version), string(id.Version),
	); err != nil {
		return rejectConfirm(ctx, cn, &th, hs, reasonVersion, err)
	}
	dec, err := decideResume(
		in, string(id.ResumeSID), binder, id.Key, thIID,
	)
	if err != nil {
		return failHS(cn, err)
	}
	if err = liftVerify(cn, in.verifyTimeout); err != nil {
		return failHS(cn, err)
	}
	sidHint := ""
	if dec.resumed {
		sidHint = string(id.ResumeSID)
	}
	err = runVerifier(ctx, in.verifyTimeout, in.verify, in.store, VerifyRequest{
		Peer: &storage.Peer{
			Name: string(id.Name), PublicKey: bytes.Clone(id.Key),
			AppVersion: string(id.Version),
		},
		LocalPublicKey: local,
		SessionID:      sidHint,
		Role:           RoleResponder,
		Pinned:         pinned,
		Resumed:        dec.resumed,
	})
	if err != nil {
		if dec.resumed && in.store != nil {
			_ = in.store.DeleteResumption(
				sidHint, storage.ResumeRoleResponder, dec.row.Generation,
			)
		}
		_, _ = rejectConfirm(ctx, cn, &th, hs, reasonVerifier, err)
		return failHS(cn, fmt.Errorf("%w: %w", ErrVerificationFailed, err))
	}
	if err = ctx.Err(); err != nil {
		return failHS(cn, fmt.Errorf("%w: %w", ErrClosedServer, err))
	}
	psk := []byte(nil)
	if dec.resumed {
		psk, err = resPSK(dec.used)
		if err != nil {
			return failHS(cn, err)
		}
	}
	status := byte(confirmCold)
	sid := ""
	if dec.resumed {
		status = confirmResumed
		sid = string(id.ResumeSID)
	}
	sess, plain, err := buildConfirm(
		&th, hs.hs, psk, status, 0, in.name, versionOf(in.version),
	)
	if err != nil {
		return failHS(cn, err)
	}
	if sid == "" {
		sid = base32.StdEncoding.EncodeToString(sess.sid)
	}
	gen, stored, err := commitResponder(
		in, sid, dec, id.Key, sess.resNext, dec.resumed,
	)
	if errors.Is(err, storage.ErrResumptionConflict) {
		return failHS(cn, err)
	}
	if err != nil {
		slog.Warn(
			"resumption commit failed",
			slog.String("session_id", sid),
			slog.Any("error", err),
		)
		gen = 0
		stored = false
	}
	sealed, err = sealHS(hs.rKey, plain, protocolVersion, frameConfirm)
	if err != nil {
		return failHS(cn, err)
	}
	if err = writeHS(ctx, cn, sealed); err != nil {
		return failHS(cn, err)
	}
	_ = cn.SetDeadline(time.Time{})
	if !stored {
		in.noPersistence = true
	}
	return newHSTransport(
		cn, in.attest, in.store, in.clock, sid, string(id.Name),
		string(id.Version), id.Key, sess.rApp, sess.iApp, sess.exporter,
		gen, storage.ResumeRoleResponder, dec.resumed, in.noPersistence,
	)
}

func loadOffer(in initiatorInput) (*storage.Resumption, error) {
	if in.noPersistence {
		return nil, fmt.Errorf(
			"%w: persistence is off", ErrNoResumptionState,
		)
	}
	if in.store == nil {
		return nil, ErrNoResumptionState
	}
	row, err := in.store.GetResumption(
		in.resumeSID, storage.ResumeRoleInitiator,
	)
	if errors.Is(err, storage.ErrNoResumption) {
		return nil, ErrNoResumptionState
	}
	if err != nil {
		return nil, err
	}
	if len(in.pin) > 0 && !bytes.Equal(in.pin, row.PeerKey) {
		return nil, ErrPeerKeyMismatch
	}
	if _, err = in.store.FindPeer(row.PeerKey); err != nil {
		if !storage.IsPeerAbsent(err) {
			return nil, err
		}
		_ = in.store.DeleteResumption(
			in.resumeSID, storage.ResumeRoleInitiator, row.Generation,
		)
		return nil, ErrNoResumptionState
	}
	return row, nil
}

func decideResume(
	in responderInput, sid string, binder, keyI, thIID []byte,
) (resumeDecision, error) {
	var d resumeDecision
	if sid == "" || !in.resumeEnabled || in.noPersistence || in.store == nil {
		return d, nil
	}
	row, err := in.store.GetResumption(sid, storage.ResumeRoleResponder)
	if errors.Is(err, storage.ErrNoResumption) {
		return d, nil
	}
	if err != nil {
		// §15.3 continues cold whenever resumed is false, including
		// when the row cannot be read.
		slog.Warn(
			"resumption read failed",
			slog.String("session_id", sid),
			slog.Any("error", err),
		)
		return d, nil
	}
	if !bytes.Equal(row.PeerKey, keyI) {
		return d, nil
	}
	if _, err = in.store.FindPeer(keyI); err != nil {
		if !storage.IsPeerAbsent(err) {
			return d, err
		}
		return d, nil
	}
	now := clockNow(in.clock)
	if now.Sub(row.RefreshedAt) > defaultResumeIdle ||
		now.Sub(row.ColdAt) > defaultResumeMaxAge {
		return d, nil
	}
	okCur, err := binderMatches(row.Current, binder, thIID)
	if err != nil {
		return d, err
	}
	okPrev := false
	if len(row.Previous) == hashLen {
		okPrev, err = binderMatches(row.Previous, binder, thIID)
		if err != nil {
			return d, err
		}
	}
	if !okCur && !okPrev {
		return d, nil
	}
	d.resumed = true
	d.row = row
	if okCur {
		d.used = row.Current
	} else {
		d.used = row.Previous
	}
	return d, nil
}

func binderMatches(res, binder, thIID []byte) (bool, error) {
	if len(res) != hashLen {
		return false, nil
	}
	key, err := binderKey(res)
	if err != nil {
		return false, err
	}
	return hmac.Equal(binder, macSHA512(key, thIID)), nil
}

func commitInitiator(
	in initiatorInput, offer *storage.Resumption, sid string,
	peerKey, resNext []byte, resumed bool,
) (uint64, error) {
	if in.noPersistence || in.store == nil {
		return 0, nil
	}
	now := clockNow(in.clock)
	if resumed {
		next := &storage.Resumption{
			Generation: offer.Generation + 1, Current: bytes.Clone(resNext),
			PeerKey: bytes.Clone(peerKey), ColdAt: offer.ColdAt,
			RefreshedAt: now, Role: storage.ResumeRoleInitiator,
		}
		err := in.store.SwapResumption(sid, offer.Generation, next)
		if errors.Is(err, storage.ErrResumptionConflict) {
			dropConflicted(in.store, sid)
			return 0, nil
		}
		if err != nil {
			slog.Warn(
				"resumption commit failed",
				slog.String("session_id", sid), slog.Any("error", err),
			)
			return 0, nil
		}
		return next.Generation, nil
	}
	if offer != nil {
		_ = in.store.DeleteResumption(
			in.resumeSID, storage.ResumeRoleInitiator, offer.Generation,
		)
	}
	next := &storage.Resumption{
		Generation: 1, Current: bytes.Clone(resNext),
		PeerKey: bytes.Clone(peerKey), ColdAt: now, RefreshedAt: now,
		Role: storage.ResumeRoleInitiator,
	}
	err := in.store.SwapResumption(sid, 0, next)
	if errors.Is(err, storage.ErrResumptionConflict) {
		dropConflicted(in.store, sid)
		return 0, nil
	}
	if err != nil {
		slog.Warn(
			"resumption commit failed",
			slog.String("session_id", sid), slog.Any("error", err),
		)
		return 0, nil
	}
	return 1, nil
}

func commitResponder(
	in responderInput, sid string, dec resumeDecision,
	peerKey, resNext []byte, resumed bool,
) (uint64, bool, error) {
	if in.noPersistence || in.store == nil {
		return 0, false, nil
	}
	now := clockNow(in.clock)
	next := &storage.Resumption{
		Current: bytes.Clone(resNext), PeerKey: bytes.Clone(peerKey),
		RefreshedAt: now, Role: storage.ResumeRoleResponder,
	}
	oldGen := uint64(0)
	if resumed {
		oldGen = dec.row.Generation
		next.Generation = dec.row.Generation + 1
		next.Previous = bytes.Clone(dec.used)
		next.ColdAt = dec.row.ColdAt
	} else {
		next.Generation = 1
		next.ColdAt = now
	}
	if err := in.store.SwapResumption(sid, oldGen, next); err != nil {
		return 0, false, err
	}
	return next.Generation, true, nil
}

func dropConflicted(store *storage.Storage, sid string) {
	row, err := store.GetResumption(sid, storage.ResumeRoleInitiator)
	if err != nil {
		return
	}
	_ = store.DeleteResumption(
		sid, storage.ResumeRoleInitiator, row.Generation,
	)
	slog.Warn(
		"resumption commit conflict",
		slog.String("session_id", sid),
		slog.Any("error", storage.ErrResumptionConflict),
	)
}

func rejectConfirm(
	ctx context.Context, cn Conn, th *transcript, hs hsKeys,
	reason byte, cause error,
) (*Transport, error) {
	_, plain, err := buildConfirm(
		th, hs.hs, nil, confirmRejected, reason, "", "",
	)
	if err != nil {
		return failHS(cn, err)
	}
	sealed, err := sealHS(hs.rKey, plain, protocolVersion, frameConfirm)
	if err != nil {
		return failHS(cn, err)
	}
	if err = writeHS(ctx, cn, sealed); err != nil {
		return failHS(cn, err)
	}
	if reason == reasonVersion {
		return failHS(cn, cause)
	}
	return failHS(cn, fmt.Errorf("%w: %w", ErrVerificationFailed, cause))
}

func buildConfirm(
	th *transcript, hsSecret, psk []byte, status, reason byte,
	name, version string,
) (appSecrets, []byte, error) {
	var zero appSecrets
	master, err := masterSecret(hsSecret, pskOrZero(psk))
	if err != nil {
		return zero, nil, err
	}
	cKey, err := confirmKey(master)
	if err != nil {
		return zero, nil, err
	}
	body, err := encodeConfirmBody(status, reason, name, version)
	if err != nil {
		return zero, nil, err
	}
	th.add(0x30, body)
	fin := macSHA512(cKey, th.sum())
	th.add(0x31, fin)
	plain, err := encodeConfirm(status, reason, name, version, fin)
	if err != nil {
		return zero, nil, err
	}
	if status == confirmRejected {
		return zero, plain, nil
	}
	sess, err := sessionSecrets(master, th.sum())
	if err != nil {
		return zero, nil, err
	}
	return sess, plain, nil
}

func newHSTransport(
	cn Conn, at *attest.Attest, store *storage.Storage, clk clock.Clock,
	sid, name, version string, peerKey, encKey, decKey, exp []byte,
	gen uint64, role storage.ResumeRole, resumed, noPersistence bool,
) (*Transport, error) {
	encoder, err := enigma.NewFromKey(encKey)
	if err != nil {
		return failHS(cn, err)
	}
	decoder, err := enigma.NewFromKey(decKey)
	if err != nil {
		return failHS(cn, err)
	}
	t := newTransport(cn, newSignedSerde(peerKey, at), sid, encoder, decoder)
	t.remotePeer = &storage.Peer{
		Name: name, PublicKey: bytes.Clone(peerKey), AppVersion: version,
	}
	t.resGen = gen
	t.resRole = role
	t.exporter = bytes.Clone(exp)
	t.resumed = resumed
	t.clock = clk
	t.takeAcceptedMeta(cn)
	if !noPersistence {
		t.storage = store
	}
	t.holdResumption()
	return t, nil
}

func failHS(cn Conn, err error) (*Transport, error) {
	_ = cn.Close()
	return nil, err
}

func readHS(ctx context.Context, cn Conn) ([]byte, error) {
	b, err := cn.ReadBytes()
	if err != nil {
		return nil, withContext(ctx, fmt.Errorf("reading handshake: %w", err))
	}
	return b, nil
}

func writeHS(ctx context.Context, cn Conn, frame []byte) error {
	if err := cn.WriteBytes(frame); err != nil {
		return withContext(ctx, fmt.Errorf("writing handshake: %w", err))
	}
	return nil
}

// withContext attaches ctx.Err when the handshake context is already done.
func withContext(ctx context.Context, err error) error {
	if err == nil || ctx == nil || ctx.Err() == nil {
		return err
	}
	return fmt.Errorf("%w: %w", err, ctx.Err())
}

func verifyTimeoutOrDefault(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return defaultVerifyTimeout
	}
	return timeout
}

func randomHello() (nonce, tag []byte, err error) {
	nonce = make([]byte, helloNonceLen)
	tag = make([]byte, helloNonceLen)
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	if _, err = rand.Read(tag); err != nil {
		return nil, nil, err
	}
	return nonce, tag, nil
}

func signedTH(ctx string, th []byte) []byte {
	out := make([]byte, 0, len(ctx)+len(th))
	out = append(out, ctx...)
	return append(out, th...)
}

func allowPeer(cn Conn, key []byte) (ran, ok bool) {
	c, ran := cn.(PeerConstraint)
	if !ran {
		return false, false
	}
	return true, c.AllowPeer(key)
}

func liftVerify(cn Conn, timeout time.Duration) error {
	limit := verifyTimeoutOrDefault(timeout)
	return cn.SetDeadline(time.Now().Add(limit))
}

func versionOf(v string) string {
	if v == "" {
		return AppVersion
	}
	return v
}

func clockNow(c clock.Clock) time.Time {
	if c == nil {
		return time.Now()
	}
	return c.Now()
}

func pskOrZero(psk []byte) []byte {
	if len(psk) == hashLen {
		return psk
	}
	return make([]byte, hashLen)
}
