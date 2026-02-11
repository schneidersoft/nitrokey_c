#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winscard.h>
#include <wintypes.h>

#include "curve25519/include/ed25519_signature.h"

/*
BEGIN KEY MATERIAL
*/

static const uint8_t fingerprint[60] = {
    0xbd, 0x8f, 0x67, 0xc8, 0x2c, 0x64, 0x00, 0xbc, 0x8a, 0x35, 0xc9, 0xec, 0xb5, 0xa8, 0x5a, 0x1e,
    0xb0, 0x78, 0x90, 0xff, 0x8f, 0x90, 0xa4, 0x2c, 0xaf, 0xee, 0x87, 0x6c, 0xf3, 0x9a, 0x28, 0x51,
    0x20, 0x58, 0x35, 0xac, 0xad, 0x45, 0xa8, 0xf0, 0xae, 0x07, 0xbc, 0xa0, 0xfc, 0x8d, 0xd4, 0x42,
    0xb1, 0xc6, 0xcd, 0xb8, 0x37, 0x31, 0xd9, 0x05, 0x08, 0x18, 0x6d, 0xfb
};
static const uint8_t pubkey[32] = {
    0xb5, 0xe0, 0x8a, 0xb8, 0xb0, 0x87, 0xbb, 0x51, 0xdb, 0xa8, 0x1b, 0x5d, 0xd4, 0xba, 0xcb, 0xc5,
    0xb4, 0x9f, 0x21, 0xfb, 0xd5, 0xce, 0xa2, 0xd9, 0x04, 0x7f, 0x23, 0xe6, 0xdc, 0x30, 0x5d, 0x03
};
static const char nitrokey_pin[] = "123456";

/*
END KEY MATERIAL
*/

#define CHALLENGE_LEN 32
#define SIG_LEN 64

static void dbg(int line, const char *fmt, ...);
#define DBG(...) dbg(__LINE__, __VA_ARGS__);

static void dbg(int line, const char *fmt, ...) {
    fprintf(stderr, "% 5d: ", line);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

static void random_bytes(unsigned char *buf, size_t len) {
    srand((unsigned)time(NULL));
    for (size_t i = 0; i < len; i++)
        buf[i] = rand() & 0xFF;
}

static int select_aid(SCARDHANDLE card, DWORD proto, const BYTE *aid, size_t aid_len) {
    BYTE apdu[5 + 16];
    BYTE resp[256];
    DWORD resp_len = sizeof(resp);
    apdu[0] = 0x00;
    apdu[1] = 0xA4;
    apdu[2] = 0x04;
    apdu[3] = 0x00;
    apdu[4] = aid_len;
    if (aid_len > 16)
        return 0;
    memcpy(&apdu[5], aid, aid_len);

    SCARD_IO_REQUEST *pci = NULL;
    if (proto == SCARD_PROTOCOL_T0)
        pci = (SCARD_IO_REQUEST *)SCARD_PCI_T0;
    else if (proto == SCARD_PROTOCOL_T1)
        pci = (SCARD_IO_REQUEST *)SCARD_PCI_T1;
    else
        return 0;

    LONG rv = SCardTransmit(card, pci, apdu, 5 + aid_len, NULL, resp, &resp_len);

    if (rv != SCARD_S_SUCCESS || resp_len < 2)
        return 0;

    return resp[resp_len - 2] == 0x90 && resp[resp_len - 1] == 0x00;
}

static int send_pin(SCARDHANDLE card, DWORD proto, const char *pin) {
    BYTE apdu[5 + 16];
    BYTE resp[256];
    DWORD resp_len = sizeof(resp);
    int len = strlen(pin);
    apdu[0] = 0x00;
    apdu[1] = 0x20;
    apdu[2] = 0x00;
    apdu[3] = 0x81;
    apdu[4] = len;
    if (len > 16)
        return 0;
    memcpy(&apdu[5], pin, len);

    SCARD_IO_REQUEST *pci = NULL;
    if (proto == SCARD_PROTOCOL_T0)
        pci = (SCARD_IO_REQUEST *)SCARD_PCI_T0;
    else if (proto == SCARD_PROTOCOL_T1)
        pci = (SCARD_IO_REQUEST *)SCARD_PCI_T1;
    else
        return 0;

    LONG rv = SCardTransmit(card, pci, apdu, 5 + len, NULL, resp, &resp_len);
    if (rv != SCARD_S_SUCCESS || resp_len < 2)
        return 0;

    BYTE sw1 = resp[resp_len - 2];
    BYTE sw2 = resp[resp_len - 1];

    if (sw1 == 0x63 && (sw2 & 0xC0) == 0xC0) {
        int retries = sw2 & 0x0F;
        DBG("Wrong PIN, %d retries left", retries);
    }

    return sw1 == 0x90 && sw2 == 0x00;
}

static int get_fingerprint(SCARDHANDLE card, DWORD proto, uint8_t *fp, uint64_t *fplen) {
    BYTE apdu[5] = { 0x00, 0xCA, 0x00, 0xC5, 0x00 };
    BYTE resp[256];
    DWORD resp_len = sizeof(resp);

    SCARD_IO_REQUEST *pci = NULL;
    if (proto == SCARD_PROTOCOL_T0)
        pci = (SCARD_IO_REQUEST *)SCARD_PCI_T0;
    else if (proto == SCARD_PROTOCOL_T1)
        pci = (SCARD_IO_REQUEST *)SCARD_PCI_T1;
    else
        return 0;

    LONG rv = SCardTransmit(card, pci, apdu, 5, NULL, resp, &resp_len);
    if (rv != SCARD_S_SUCCESS || resp_len < 2)
        return 0;

    BYTE sw1 = resp[resp_len - 2];
    BYTE sw2 = resp[resp_len - 1];

    if (sw1 == 0x90 && sw2 == 0x00) {
        resp_len -= 2;
        if (*fplen <= resp_len) {
            resp_len = *fplen;
        }

        memcpy(fp, resp, resp_len);
        *fplen = resp_len;

    }

    return sw1 == 0x90 && sw2 == 0x00;
}

static int sign_challenge(SCARDHANDLE card, DWORD proto, unsigned char *challenge, unsigned char *signature, DWORD *sig_len) {
    BYTE apdu[5 + CHALLENGE_LEN];
    DWORD apdu_len = 5 + CHALLENGE_LEN;

    apdu[0] = 0x00;
    apdu[1] = 0x2A;
    apdu[2] = 0x9E;
    apdu[3] = 0x9A;
    apdu[4] = CHALLENGE_LEN;

    memcpy(&apdu[5], challenge, CHALLENGE_LEN);

    SCARD_IO_REQUEST *pci = NULL;
    if (proto == SCARD_PROTOCOL_T0)
        pci = (SCARD_IO_REQUEST *)SCARD_PCI_T0;
    else if (proto == SCARD_PROTOCOL_T1)
        pci = (SCARD_IO_REQUEST *)SCARD_PCI_T1;
    else
        return 0;

    DWORD resp_len = *sig_len;
    LONG rv = SCardTransmit(card, pci, apdu, apdu_len, NULL, signature, &resp_len);
    if (rv != SCARD_S_SUCCESS || resp_len < 2)
        return 0;

    BYTE sw1 = signature[resp_len - 2];
    BYTE sw2 = signature[resp_len - 1];

    // Handle 61 XX
    uint32_t rem = *sig_len;
    *sig_len = 0;
    while (sw1 == 0x61) {
        // Card says "response available"
        // DWORD get_len = 300; // buffer length for signature
        // if (*sig_len < get_len) get_len = *sig_len; // cap to provided buffer

        BYTE get_resp_apdu[512] = {0x00, 0xC0, 0x00, 0x00, 0x00};
        resp_len = rem > 255 ? 255 : rem;
        get_resp_apdu[4] = resp_len; // Le = 0 means fetch as much as fits
        resp_len += 2;

        rv = SCardTransmit(card, pci, get_resp_apdu, 5, NULL, signature, &resp_len);
        if (rv != SCARD_S_SUCCESS || resp_len < 2) {
            DBG("GET RESPONSE failed: rv=%08x resp_len=%lu", rv, resp_len);
            return 0;
        }

        sw1 = signature[resp_len - 2];
        sw2 = signature[resp_len - 1];
        signature += resp_len - 2;
        *sig_len += resp_len - 2;
        rem -= resp_len - 2;
    }

    if (sw1 != 0x90 || sw2 != 0x00)
        return 0;

    DBG("siglen %d", *sig_len);
    return 1;
}

static int try_reader(SCARDHANDLE card, DWORD active_protocol) {
    LONG rv;
    // SELECT application (GPG)
    uint8_t aid[] = {0xD2, 0x76, 0x00, 0x01, 0x24, 0x01};
    rv = select_aid(card, active_protocol, aid, sizeof(aid));
    if (!rv) {
        DBG("select_aid failed");
        return 1;
    } else {
        DBG("select_aid SUCCESS");
    }

    // get and match the fingerprint
    BYTE fprnt[256];
    DWORD fprntlen = sizeof(fprnt);
    rv = get_fingerprint(card, active_protocol, fprnt, &fprntlen);
    if (!rv) {
        DBG("get_fingerprint");
        return 1;
    } else {
        DBG("get_fingerprint SUCCESS");
        //DBG_HEX(fprnt, fprntlen, "fprnt: ");
        if (sizeof(fingerprint) != fprntlen || 0 != memcmp(fingerprint, fprnt, sizeof(fingerprint))) {
            DBG("fingerprint missmatch");
            return 1;
        }
    }

    // unlock with pin
    rv = send_pin(card, active_protocol, nitrokey_pin);
    if (!rv) {
        DBG("send_pin");
        return 1;
    } else {
        DBG("send_pin SUCCESS");
    }

    // do challenger / response
    unsigned char challenge[CHALLENGE_LEN];
    unsigned char signature[SIG_LEN+1];
    DWORD sig_len = sizeof(signature);

    random_bytes(challenge, CHALLENGE_LEN);
    rv = sign_challenge(card, active_protocol, challenge, signature, &sig_len);
    if (rv == 1) {
        DBG("SUCCESS - Got signature");

        int ret = ed25519_VerifySignature(signature,      /* IN: [64 bytes] signature (R,S) */
                                          pubkey,         /* IN: [32 bytes] public key */
                                          challenge,      /* IN: [msg_size bytes] message that was signed */
                                          CHALLENGE_LEN); /* IN: size of message */
        if (ret) {
            DBG("SUCCESS - AUTHORIZED");
        }
    } else {
        DBG("FAILED");
    }
    return 0;
}

int main(void) {
    SCARDCONTEXT ctx;
    LONG rv;

    // Establish context
    rv = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &ctx);
    if (rv != SCARD_S_SUCCESS) {
        DBG("SCardEstablishContext failed");
        return 1;
    }

    // itterate ver all readers
    char readers[1024];
    DWORD readers_len = sizeof(readers);

    rv = SCardListReaders(ctx, NULL, readers, &readers_len);
    if (rv != SCARD_S_SUCCESS) {
        DBG("No smartcard readers found");
        return 1;
    }

    char *p = readers;
    while (*p) {
        // check each smart card
        DBG("Trying: %s", p);

        SCARDHANDLE card;
        DWORD active_protocol;
        rv = SCardConnect(ctx, p, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card, &active_protocol);
        if (rv != SCARD_S_SUCCESS) {
            DBG("SCardConnect failed");
        } else {
            try_reader(card, active_protocol);
            SCardDisconnect(card, SCARD_LEAVE_CARD);
        }

        p += strlen(p) +1;
    }

    SCardReleaseContext(ctx);

    return 0;
}
