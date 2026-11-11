#ifndef NORTHSTAR_XOR_H
#define NORTHSTAR_XOR_H

/*
 * Repeating-key XOR specification for the Northstar License Manager.
 *
 * Authoritative copy of the key: shared/xor-spec.json
 *
 *     C[i] = P[i] XOR K[i % n]
 *     P[i] = C[i] XOR K[i % n]
 *
 * license.dat stores C, the encoded license. This executable holds K and
 * applies it to whatever the operator types in.
 */
static const unsigned char NORTHSTAR_XOR_KEY[] = "NorthstarK3y";

#define NORTHSTAR_XOR_KEY_LEN (sizeof(NORTHSTAR_XOR_KEY) - 1u)

/* Longest license the tool accepts, matching maxPlaintextBytes in the spec. */
#define NORTHSTAR_MAX_LICENSE 128

#endif /* NORTHSTAR_XOR_H */
