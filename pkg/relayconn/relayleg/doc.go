// Package relayleg is the relay leg v2 of RFC 009.
//
// This commit has the keys: the relay static key, its PEM file, and
// the access key (PSK). The handshake and the record channel are not
// in this package yet.
//
// Section 11.5 of RFC 009 is the contract for the private key. Outside
// this package it is reachable only through [PrivateKey.ExtractShared].
// There is no accessor for the scalar, the `*ecdh.PrivateKey`, or a
// raw DH output. The key never signs.
package relayleg
