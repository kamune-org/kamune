// Package relayleg is the relay leg v2 of RFC 009.
//
// The package has the relay static key, the access key, the handshake
// (FetchKey, Initiate and Accept) and the record channel. A relay that
// holds an access key rejects every other first frame in silence.
//
// Section 11.5 of RFC 009 is the contract for the private key. Outside
// this package it is reachable only through [PrivateKey.ExtractShared].
// There is no accessor for the scalar, the *ecdh.PrivateKey, or a
// raw DH output. The key never signs.
package relayleg
