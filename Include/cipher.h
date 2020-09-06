/*
 *
 * University of Luxembourg
 * Laboratory of Algorithmics, Cryptology and Security (LACS)
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 University of Luxembourg
 *
 * Written in 2015 by Daniel Dinu <dumitru-daniel.dinu@uni.lu> and 
 * Yann Le Corre <yann.lecorre@uni.lu>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef CIPHER_H
#define CIPHER_H


/*
 *
 * Optimization levels
 * ... OPTIMIZATION_LEVEL_0 - O0
 * ... OPTIMIZATION_LEVEL_1 - O1
 * ... OPTIMIZATION_LEVEL_2 - O2
 * ... OPTIMIZATION_LEVEL_3 - O3 = defualt
 *
 */
#define OPTIMIZATION_LEVEL_0 __attribute__((optimize("O0")))
#define OPTIMIZATION_LEVEL_1 __attribute__((optimize("O1")))
#define OPTIMIZATION_LEVEL_2 __attribute__((optimize("O2")))
#define OPTIMIZATION_LEVEL_3 __attribute__((optimize("O3")))


/*
 *
 * Align memory boundaries in bytes
 *
 */
#define ALIGN_BOUNDRY 8

#if !defined(ALIGNED) 
#define ALIGNED __attribute__ ((aligned(ALIGN_BOUNDRY)))
#endif


/* 
 *
 * RAM data types 
 *
 */
#define RAM_DATA_BYTE uint8_t ALIGNED
#define RAM_DATA_WORD uint16_t ALIGNED
#define RAM_DATA_DOUBLE_WORD uint32_t ALIGNED

#define READ_RAM_DATA_BYTE(x) x
#define READ_RAM_DATA_WORD(x) x
#define READ_RAM_DATA_DOUBLE_WORD(x) x


/* 
 *
 * Flash/ROM data types 
 *
 */
#define ROM_DATA_BYTE const uint8_t ALIGNED
#define ROM_DATA_WORD const uint16_t ALIGNED
#define ROM_DATA_DOUBLE_WORD const uint32_t ALIGNED

#define READ_ROM_DATA_BYTE(x) x
#define READ_ROM_DATA_WORD(x) x
#define READ_ROM_DATA_DOUBLE_WORD(x) x


/*
 *
 * round keys are stored in Flash/ROM or RAM
 *
 */
#define ROM_ROUNDKEY
#if defined(ROM_ROUNDKEY)
#define READ_ROUND_KEY_BYTE(x) READ_ROM_DATA_BYTE(x)
#define READ_ROUND_KEY_WORD(x) READ_ROM_DATA_WORD(x)
#define READ_ROUND_KEY_DOUBLE_WORD(x) READ_ROM_DATA_DOUBLE_WORD(x)
#else
#define READ_ROUND_KEY_BYTE(x) READ_RAM_DATA_BYTE(x)
#define READ_ROUND_KEY_WORD(x) READ_RAM_DATA_WORD(x)
#define READ_ROUND_KEY_DOUBLE_WORD(x) READ_RAM_DATA_DOUBLE_WORD(x)
#endif


/*
 *
 * Run the encryption key schedule
 * ... key - the cipher key
 * ... roundKeys - the encryption round keys
 *
 */
void RunEncryptionKeySchedule(uint8_t *key, uint8_t *roundKeys);

/*
 *
 * Run the decryption key schedule
 * ... key - the cipher key
 * ... roundKeys - the decryption round keys
 *
 */
void RunDecryptionKeySchedule(uint8_t *key, uint8_t *roundKeys);

/*
 *
 * Encrypt the given block using the given round keys
 * ... block - the block to encrypt
 * ... roundKeys - the round keys to be used during encryption
 *
 */
void Encrypt(uint8_t *block, uint8_t *roundKeys);

/*
 *
 * Decrypt the given block using the given round keys
 * ... block - the block to decrypt
 * ... roundKeys - the round keys to be used during decryption
 *
 */
void Decrypt(uint8_t *block, uint8_t *roundKeys);

#endif /* CIPHER_H */
