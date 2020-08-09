#! /usr/bin/env python3

import binascii
import hashlib
import hmac
import io
import json
import os
import random
import sys

import umsgpack
import nacl.bindings
from nacl.exceptions import CryptoError

from . import armor
from . import error
from .debug import debug, tohex
from .encrypt import json_repr, chunks_loop


# All the important bits!
# -----------------------

SENDER_KEY_SECRETBOX_NONCE = b"saltpack_sender_key_sbox"
assert len(SENDER_KEY_SECRETBOX_NONCE) == 24

PAYLOAD_KEY_BOX_NONCE_PREFIX_V2 = b"saltpack_recipsb"
assert len(PAYLOAD_KEY_BOX_NONCE_PREFIX_V2) == 16

PAYLOAD_NONCE_PREFIX = b"saltpack_ploadsb"
assert len(PAYLOAD_NONCE_PREFIX) == 16

SHARED_SYM_KEY_NONCE = b"saltpack_derived_sboxkey"
assert len(SHARED_SYM_KEY_NONCE) == 24

SHARED_SYM_HMAC_KEY = b"saltpack signcryption derived symmetric key"
assert len(SHARED_SYM_HMAC_KEY) == 43

SIGNCRYPTION_BOX_KEY_ID_HMAC_KEY = b"saltpack signcryption box key identifier"
assert len(SIGNCRYPTION_BOX_KEY_ID_HMAC_KEY) == 40

SIGNCRYPTION_SALTPACK_ENCRYPTED_SIGNATURE_STRING = b"saltpack encrypted signature"
assert len(SIGNCRYPTION_SALTPACK_ENCRYPTED_SIGNATURE_STRING) == 28

DEFAULT_MAJOR_VERSION = 2
CURRENT_MINOR_VERSIONS = {1: 0, 2: 0}

CURRENT_MAJOR_VERSION = DEFAULT_MAJOR_VERSION
CURRENT_MINOR_VERSION = CURRENT_MINOR_VERSIONS[CURRENT_MAJOR_VERSION]


def signcrypt(sender_private_signing, public_recipient_keys, symmetric_recipient_keys, message, chunk_size, *,
            anon_sender=False, shuffle=False, major_version=None):
    # If sender wishes to remain anonymous, use all zeros for signing key
    if anon_sender:
        sender_public_signing = b'\0'*32;
    else:
        sender_public_signing = sender_private_signing[32:]
    ephemeral_private = os.urandom(32)
    ephemeral_public = nacl.bindings.crypto_scalarmult_base(ephemeral_private)
    payload_key = os.urandom(32)

    sender_secretbox = nacl.bindings.crypto_secretbox(
        message=sender_public_signing,
        nonce=SENDER_KEY_SECRETBOX_NONCE,
        key=payload_key)

    if major_version is None:
        major_version = DEFAULT_MAJOR_VERSION

    recipient_pairs = []
    recipient_list = []
    for recipient_key in symmetric_recipient_keys:
        recipient_list.append([recipient_key,"S"])
    for recipient_key in public_recipient_keys:
        recipient_list.append([recipient_key,"P"])

    # shuffle recipient list to prevent inferring information from recipient order
    if shuffle:
        random.shuffle(recipient_list)

    for recipient_index, recipient_key_and_type in enumerate(recipient_list):
        recipient_key, key_type = recipient_key_and_type
        assert len(recipient_key) == 32
        if key_type == "S":
            hmac_digest = hmac.new(SHARED_SYM_HMAC_KEY, digestmod=hashlib.sha512)
            hmac_digest.update(ephemeral_public + recipient_key)
            shared_sym_key = hmac_digest.digest()[:32]
    
            payload_secretbox = nacl.bindings.crypto_secretbox(
                message=payload_key,
                nonce=PAYLOAD_KEY_BOX_NONCE_PREFIX_V2 + recipient_index.to_bytes(8, "big"),
                key=shared_sym_key)
            # Key identifier for shared symmetric recipient key left to application
            # Leaving blank for now
            key_id = b''
            pair = [key_id, payload_secretbox]
            recipient_pairs.append(pair)
        elif key_type == "P":
            shared_key_box = nacl.bindings.crypto_box(
                message=b'\0'*32,
                nonce=SHARED_SYM_KEY_NONCE,
                pk=recipient_key,
                sk=ephemeral_private)
            shared_sym_key = shared_key_box[-32:]
    
            payload_secretbox = nacl.bindings.crypto_secretbox(
                message=payload_key,
                nonce=PAYLOAD_KEY_BOX_NONCE_PREFIX_V2 + recipient_index.to_bytes(8, "big"),
                key=shared_sym_key)
            hmac_digest = hmac.new(SIGNCRYPTION_BOX_KEY_ID_HMAC_KEY, digestmod=hashlib.sha512)
            hmac_digest.update(shared_sym_key + PAYLOAD_KEY_BOX_NONCE_PREFIX_V2 + recipient_index.to_bytes(8, "big"))
            key_id = hmac_digest.digest()[:32]
            pair = [key_id, payload_secretbox]
            recipient_pairs.append(pair)


    header = [
        # format name
        "saltpack",  # format name
        [major_version, CURRENT_MINOR_VERSIONS[major_version]],
        # mode (signcryption)
        3,
        ephemeral_public,
        sender_secretbox,
        recipient_pairs,
    ]
    header_bytes = umsgpack.packb(header)
    header_hash = nacl.bindings.crypto_hash(header_bytes)
    double_encoded_header_bytes = umsgpack.packb(header_bytes)
    output = io.BytesIO()
    output.write(double_encoded_header_bytes)

    # Write the chunks.
    for chunknum, chunk, final_flag in chunks_loop(message, chunk_size, major_version):
        payload_nonce = bytearray(header_hash[:16])
        if final_flag:
            payload_nonce[15] |= 1  # set the last bit
        else:
            payload_nonce[15] &= 254  # clear the last bit
        packet_nonce = bytes(payload_nonce) + chunknum.to_bytes(8, "big")
        final_flag_byte = b"\x01" if final_flag else b"\x00"
        payload_digest = hashlib.sha512(chunk).digest()
        payload_sig_text = SIGNCRYPTION_SALTPACK_ENCRYPTED_SIGNATURE_STRING + b'\0' + header_hash + packet_nonce + final_flag_byte + payload_digest
        if anon_sender:
            payload_sig = b'\0'*64
        else:
            payload_sig = nacl.bindings.crypto_sign(payload_sig_text, sender_private_signing)
            payload_sig = payload_sig[:64]
        sig_and_chunk = payload_sig + chunk
        sigchunk_secretbox = nacl.bindings.crypto_secretbox(
                message=sig_and_chunk,
                nonce=packet_nonce,
                key=payload_key)
        packet = [
                sigchunk_secretbox,
                final_flag,
        ]

        output.write(umsgpack.packb(packet))

    return output.getvalue()


def designcrypt(input, recipient_private_or_sym):
    recipient_public = nacl.bindings.crypto_scalarmult_base(recipient_private_or_sym)
    stream = io.BytesIO(input)
    payload_key = b'\0'*32
    # Parse the header.
    header_bytes = umsgpack.unpack(stream)
    header_hash = nacl.bindings.crypto_hash(header_bytes)
    header = umsgpack.unpackb(header_bytes)
    debug('header:', json_repr(header))
    debug('header hash:', header_hash)
    [
        format_name,
        [major_version, minor_version],
        mode,
        ephemeral_public,
        sender_secretbox,
        recipient_pairs,
        *_,  # ignore additional elements
    ] = header

    if format_name != "saltpack":
        raise error.BadFormatError(
            "Unrecognized format name: '{}'".format(format_name))
    if major_version not in (1, 2):
        raise error.BadVersionError(
            "Incompatible major version: {}".format(major_version))
    if mode != 3:
        raise error.BadModeError(
            "Incompatible mode: {}".format(mode))

    # Try decrypting each sender box, until we find the one that works.
    for recipient_index, pair in enumerate(recipient_pairs):
        [key_id, payload_key_box, *_] = pair
        # try asymmetric key
        shared_key_box = nacl.bindings.crypto_box(
                message=b'\0'*32,
                nonce=SHARED_SYM_KEY_NONCE,
                pk=ephemeral_public,
                sk=recipient_private_or_sym)
        shared_sym_key = shared_key_box[-32:]
        try:
            payload_key = nacl.bindings.crypto_secretbox_open(
                ciphertext=payload_key_box,
                nonce=PAYLOAD_KEY_BOX_NONCE_PREFIX_V2 + recipient_index.to_bytes(8, "big"),
                key=shared_sym_key)
            break
        except CryptoError:
            pass
        # try symmetric key
        hmac_digest = hmac.new(SHARED_SYM_HMAC_KEY, digestmod=hashlib.sha512)
        hmac_digest.update(ephemeral_public + recipient_private_or_sym)
        shared_sym_key = hmac_digest.digest()[:32]
        try:
            payload_key = nacl.bindings.crypto_secretbox_open(
            ciphertext=payload_key_box,
            nonce=PAYLOAD_KEY_BOX_NONCE_PREFIX_V2 + recipient_index.to_bytes(8, "big"),
            key=shared_sym_key)
            break
        except CryptoError:
            continue
    else:
        raise RuntimeError('Failed to find matching recipient.')

    sender_public_signing = nacl.bindings.crypto_secretbox_open(
        ciphertext=sender_secretbox,
        nonce=SENDER_KEY_SECRETBOX_NONCE,
        key=payload_key)


    debug('recipient index:', recipient_index)
    debug('sender key:', sender_public_signing)
    debug('payload key:', payload_key)

    # Decrypt each of the packets.
    output = io.BytesIO()
    chunknum = 0
    while True:
        packet = umsgpack.unpack(stream)
        debug('packet:', json_repr(packet))
        final_flag = False
        [signcrypted_chunk, final_flag] = packet

        # Verify the secretbox hash.
        payload_nonce = bytearray(header_hash[:16])
        if final_flag:
            payload_nonce[15] |= 1  # set the last bit
        else:
            payload_nonce[15] &= 254  # clear the last bit
        packet_nonce = bytes(payload_nonce) + chunknum.to_bytes(8, "big")
        debug('payload nonce:', payload_nonce)

        # Open the payload secretbox.
        sig_and_chunk = nacl.bindings.crypto_secretbox_open(
            ciphertext=signcrypted_chunk,
            nonce=packet_nonce,
            key=payload_key)
        sig = sig_and_chunk[:64]
        chunk = sig_and_chunk[64:]
        final_flag_byte = b"\x01" if final_flag else b"\x00"
        payload_digest = hashlib.sha512(chunk).digest()
        payload_sig_text = SIGNCRYPTION_SALTPACK_ENCRYPTED_SIGNATURE_STRING + b'\0' + header_hash + packet_nonce + final_flag_byte + payload_digest
        if sig == b'\0'*64:
            pass
        else:
            payload_sig_text = sig + payload_sig_text
            nacl.bindings.crypto_sign_open(payload_sig_text, sender_public_signing)
        output.write(chunk)

        debug('chunk:', repr(chunk))

        # The empty chunk or the final flag signifies the end of the message.
        if chunk == b'' or final_flag:
            break

        chunknum += 1

    return output.getvalue()


def get_private_signing(args):
    if args['<private>']:
        private = binascii.unhexlify(args['<private>'])
        assert len(private) == 64
        return private
    else:
        return b'\0'*64


def get_private(args):
    if args['<private>']:
        private = binascii.unhexlify(args['<private>'])
        assert len(private) == 32
        return private
    else:
        return b'\0'*32


def get_public_recipients(args):
    recipients = []
    if args['--pr']:
        for recipient in args['--pr']:
            key = binascii.unhexlify(recipient)
            assert len(key) == 32
            recipients.append(key)
    return recipients


def get_symmetric_recipients(args):
    recipients = []
    if args['--sr']:
        for recipient in args['--sr']:
            key = binascii.unhexlify(recipient)
            assert len(key) == 32
            recipients.append(key)
    return recipients


def do_signcrypt(args):
    if ((args['--pr'] is None) and (args['--sr'] is None)):
        print("\n[ERROR] No keys given! Please provide at least one key using --pr or --sr")
    else:
        message = args['--message']
        anon_sender = args['--anon']
        if message is None:
            encoded_message = sys.stdin.buffer.read()
        else:
            encoded_message = message.encode('utf8')
        sender = get_private_signing(args)
        if args['--chunk']:
            chunk_size = int(args['--chunk'])
        else:
            chunk_size = 10**6
        if args['--major-version']:
            major_version = int(args['--major-version'])
        else:
            major_version = None
        public_recipients = get_public_recipients(args)
        symmetric_recipients = get_symmetric_recipients(args)
        output = signcrypt(
            sender,
            public_recipients,
            symmetric_recipients,
            encoded_message,
            chunk_size,
            anon_sender=anon_sender,
            shuffle=True,
            major_version=major_version)
        if not args['--binary']:
            output = (armor.armor(output, message_type="ENCRYPTED MESSAGE") +
                    '\n').encode()
        sys.stdout.buffer.write(output)


def do_designcrypt(args):
    message = sys.stdin.buffer.read()
    if not args['--binary']:
        message = armor.dearmor(message.decode())
    private = get_private(args)
    decoded_message = designcrypt(message, private)
    sys.stdout.buffer.write(decoded_message)

def do_genkey(args):
    private = os.urandom(32)
    private = binascii.hexlify(private)
    assert len(private) == 64
    sys.stdout.buffer.write(private)

def do_pubout(args):
    private = sys.stdin.buffer.read()
    private = binascii.unhexlify(private)
    assert len(private) == 32
    public = nacl.bindings.crypto_scalarmult_base(private)
    public = binascii.hexlify(public)
    assert len(public) == 64
    sys.stdout.buffer.write(public)
