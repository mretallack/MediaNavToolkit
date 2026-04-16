/*
 * r6_swid.c — Call the SWID generation chain to understand the format
 *
 * We know: MD5("SPEEDx{serial}CAM") → 16 bytes → CK-XXXX-XXXX-XXXX-XXXX
 * We need to figure out the byte-to-char mapping in step 3.
 *
 * Approach: compute MD5 ourselves for a known serial, then try different
 * encodings to match the known SWID CK-153G-PF9R-KB6D-W8B0.
 *
 * We don't know the serial, but we can try the reverse: given the SWID,
 * figure out what MD5 bytes produce those chars.
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h>

static void md5(const char *input, unsigned char *out) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    DWORD len = 16;
    CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)input, strlen(input), 0);
    CryptGetHashParam(hHash, HP_HASHVAL, out, &len, 0);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}

int main() {
    /* Try a few known serial formats to see if we can match the SWID */
    /* The SWID CK-153G-PF9R-KB6D-W8B0 was captured from a real session */

    /* Test: compute MD5 for various serials and show the result */
    const char *serials[] = {
        "E7091067",      /* volume label without dash */
        "E709-1067",     /* volume label with dash */
        "3875893735",    /* volume serial as decimal (0xE7091067) */
        NULL
    };

    int i;
    for (i = 0; serials[i]; i++) {
        char salted[256];
        unsigned char hash[16];
        sprintf(salted, "SPEEDx%sCAM", serials[i]);
        md5(salted, hash);
        printf("Serial: %-20s Salt: %-35s MD5: ", serials[i], salted);
        int j;
        for (j = 0; j < 16; j++) printf("%02x", hash[j]);
        printf("\n");
    }

    /* Now let's try to decode the SWID chars back to nibbles/bytes */
    /* SWID: CK-153G-PF9R-KB6D-W8B0 → chars: 153GPF9RKB6DW8B0 */
    printf("\nSWID char analysis:\n");
    const char *swid = "153GPF9RKB6DW8B0";

    /* Crockford base32: 0123456789ABCDEFGHJKMNPQRSTVWXYZ */
    const char *crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    printf("Crockford indices: ");
    for (i = 0; i < 16; i++) {
        const char *p = strchr(crockford, swid[i]);
        if (p) printf("%d ", (int)(p - crockford));
        else printf("? ");
    }
    printf("\n");

    /* If Crockford base32: 16 chars * 5 bits = 80 bits = 10 bytes */
    /* Decode to bytes */
    int indices[16];
    for (i = 0; i < 16; i++) {
        const char *p = strchr(crockford, swid[i]);
        indices[i] = p ? (int)(p - crockford) : 0;
    }

    /* Pack 5-bit values into bytes */
    unsigned long long bits = 0;
    for (i = 0; i < 16; i++) {
        bits = (bits << 5) | indices[i];
    }
    /* bits is now 80 bits, stored in the top 80 bits of a conceptual 80-bit number */
    printf("Crockford decoded (10 bytes): ");
    unsigned char decoded[10];
    for (i = 9; i >= 0; i--) {
        decoded[i] = bits & 0xFF;
        bits >>= 8;
    }
    for (i = 0; i < 10; i++) printf("%02x", decoded[i]);
    printf("\n");

    /* Also try: each char is a nibble (4 bits) with custom alphabet */
    /* 16 chars * 4 bits = 64 bits = 8 bytes */
    /* Custom alphabet could be: 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ minus some */
    printf("\nNibble hypothesis (if each char = 4 bits):\n");
    /* Map: 0=0, 1=1, ..., 9=9, A=10, B=11, ..., but some letters skipped */
    /* The chars used are: 0,1,3,5,6,8,9,B,D,F,G,K,P,R,W */
    /* That's 15 unique values from 16 chars — could be hex-like */

    return 0;
}
